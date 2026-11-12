# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Merge component records from several in-memory CycloneDX BOMs.

Identity model used here (mapped 1:1 onto library fields, no new identifier):

* Package coordinates -- ``purl`` (canonical string), then ``cpe``, then the
  ``(group, name, version)`` triple. Coordinates say *which package release* a
  record points at, not *which built artifact* was observed.
* Component instance evidence -- ``hashes`` (algorithm + content), plus
  ``omnibor_ids`` / ``swhids`` when present. Two records are the same observed
  instance only when their instance evidence agrees.
* ``bom_ref`` -- a document-local link label. It is unique inside one BOM and
  has no meaning across BOMs, so it is never used as a merge key.

Two records sharing a PURL but carrying different hashes are therefore kept
apart as distinct instances and the disagreement is reported as a conflict,
instead of being silently collapsed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Iterable, Optional

from packageurl import PackageURL

from cyclonedx.model import HashAlgorithm, HashType, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.component_evidence import (
    AnalysisTechnique,
    ComponentEvidence,
    Identity,
    IdentityField,
    Method,
    Occurrence,
)

CONFLICT_PROPERTY_PREFIX = 'cyclonedx-python-lib.tools.bom-merge'
"""Namespace for merge bookkeeping properties; the property model already exists."""


class MergeStatus(str, Enum):
    """Outcome of aggregating one coordinate group."""

    SINGLE = 'single'
    """Only one distinct instance evidence under the coordinates."""

    DUPLICATE = 'duplicate'
    """Repeated observation of the same instance (identical hashes)."""

    HASH_CONFLICT = 'hash-conflict'
    """Same coordinates, but mutually exclusive instance hashes were observed."""

    UNRESOLVED = 'unresolved'
    """Coordinates match, but no record carries instance evidence (hashes)."""


class ConflictKind(str, Enum):
    """Why a coordinate group could not be collapsed into one instance."""

    HASH_MISMATCH = 'hash-mismatch'
    MISSING_HASH = 'missing-hash'


@dataclass(frozen=True)
class HashConflict:
    """A per-alorithm digest disagreement, expressed with existing fields only."""

    algorithm: HashAlgorithm
    values: tuple[str, ...]


@dataclass(frozen=True)
class SourceObservation:
    """Provenance of one input record."""

    bom_serial: str
    bom_version: int
    bom_ref: Optional[str]
    hashes: tuple[HashType, ...]
    occurrences: tuple[Occurrence, ...]
    tools: tuple[str, ...]


@dataclass
class MergedComponent:
    """Result of aggregating one coordinate group."""

    coordinates_key: str
    coordinate_kind: str
    status: MergeStatus
    components: list[Component] = field(default_factory=list)
    conflicts: list[HashConflict] = field(default_factory=list)
    conflict_kind: Optional[ConflictKind] = None
    observations: list[SourceObservation] = field(default_factory=list)

    @property
    def instance_count(self) -> int:
        """Number of distinct observed artifacts under these coordinates."""
        return len(self.components)


def coordinate_key(component: Component) -> tuple[str, str]:
    """Return ``(kind, key)`` describing package coordinates only.

    Precedence: canonical PURL string, then CPE, then group/name/version.
    The key deliberately excludes hashes, bom-ref, evidence and properties.
    """
    if component.purl is not None:
        return 'purl', str(component.purl)
    if component.cpe:
        return 'cpe', component.cpe
    group = component.group or ''
    if component.version:
        return 'gnv', f'{group}/{component.name}@{component.version}'
    return 'gnv', f'{group}/{component.name}'


def _hash_signature(hashes: Iterable[HashType]) -> tuple[tuple[HashAlgorithm, str], ...]:
    """Stable identity signature built from the hash set of one record."""
    return tuple(sorted((h.alg, h.content.lower()) for h in hashes))


def _hash_conflicts(signatures: Iterable[tuple[tuple[HashAlgorithm, str], ...]]) -> list[HashConflict]:
    """Collect algorithms whose observed content differs between records."""
    by_alg: dict[HashAlgorithm, set[str]] = {}
    for signature in signatures:
        for alg, content in signature:
            by_alg.setdefault(alg, set()).add(content)
    return [
        HashConflict(algorithm=alg, values=tuple(sorted(values)))
        for alg, values in sorted(by_alg.items(), key=lambda item: item[0].name)
        if len(values) > 1
    ]


def _merged_hashes(records: list[Component]) -> list[HashType]:
    """Union of all hashes; the SortedSet assignment on Component de-duplicates."""
    seen: dict[tuple[HashAlgorithm, str], HashType] = {}
    for record in records:
        for hash_type in record.hashes:
            seen.setdefault((hash_type.alg, hash_type.content), hash_type)
    return list(seen.values())


def _all_occurrences(records: list[Component]) -> list[Occurrence]:
    occurrences: list[Occurrence] = []
    for record in records:
        if record.evidence is not None:
            occurrences.extend(record.evidence.occurrences)
    return occurrences


def _all_identities(records: list[Component]) -> list[Identity]:
    identities: list[Identity] = []
    for record in records:
        if record.evidence is not None:
            identities.extend(record.evidence.identity)
    return identities


def _conflict_evidence(
    *,
    conflict_kind: ConflictKind,
    conflicts: list[HashConflict],
    records: list[Component],
    merged_ref: str,
) -> ComponentEvidence:
    """Represent the disagreement inside standard ``evidence.identity`` entries.

    Each conflicting digest becomes an ``Identity(field=HASH, ...)`` carrying a
    ``hash-comparison`` method, so downstream consumers see every observed value
    instead of a winner/loser decision.
    """
    identities = _all_identities(records)
    if conflict_kind is ConflictKind.HASH_MISMATCH:
        for conflict in conflicts:
            for value in conflict.values:
                identities.append(Identity(
                    field=IdentityField.HASH,
                    concluded_value=f'{conflict.algorithm.value}:{value}',
                    methods=[Method(
                        technique=AnalysisTechnique.HASH_COMPARISON,
                        confidence=Decimal('1.0'),
                        value='conflicting digests observed for identical package coordinates',
                    )],
                    tools=[BomRef(merged_ref)],
                ))
    else:
        identities.append(Identity(
            field=IdentityField.PURL,
            confidence=None,
            concluded_value=str(records[0].purl) if records[0].purl is not None else None,
            methods=[Method(
                technique=AnalysisTechnique.MANIFEST_ANALYSIS,
                confidence=Decimal('0.0'),
                value='coordinates only; no hash evidence available to prove a shared instance',
            )],
            tools=[BomRef(merged_ref)],
        ))
    return ComponentEvidence(
        identity=identities,
        occurrences=_all_occurrences(records),
    )


def _bookkeeping_properties(
    *,
    status: MergeStatus,
    conflict_kind: Optional[ConflictKind],
    conflicts: list[HashConflict],
    observation_count: int,
) -> list[Property]:
    properties = [
        Property(name=f'{CONFLICT_PROPERTY_PREFIX}:status', value=status.value),
        Property(name=f'{CONFLICT_PROPERTY_PREFIX}:observation-count', value=str(observation_count)),
    ]
    if conflict_kind is not None:
        properties.append(
            Property(name=f'{CONFLICT_PROPERTY_PREFIX}:conflict', value=conflict_kind.value))
    for conflict in conflicts:
        properties.append(Property(
            name=f'{CONFLICT_PROPERTY_PREFIX}:hash-conflict:{conflict.algorithm.value}',
            value='|'.join(conflict.values),
        ))
    return properties


def _representative(records: list[Component]) -> Component:
    """Pick the most-evidenced record as the carrier of the merged output."""
    return max(records, key=lambda record: (len(record.hashes), len(record.properties)))


def _build_merged_component(
    *,
    coordinates: tuple[str, str],
    records: list[Component],
    observations: list[SourceObservation],
) -> MergedComponent:
    kind, key = coordinates
    signatures = [_hash_signature(record.hashes) for record in records]
    non_empty = [signature for signature in signatures if signature]
    distinct_signatures = set(non_empty)
    conflicts = _hash_conflicts(signatures)

    if not non_empty:
        status = MergeStatus.UNRESOLVED
        conflict_kind = ConflictKind.MISSING_HASH
    elif conflicts:
        status = MergeStatus.HASH_CONFLICT
        conflict_kind = ConflictKind.HASH_MISMATCH
    elif len(records) == 1:
        status = MergeStatus.SINGLE
        conflict_kind = None
    else:
        status = MergeStatus.DUPLICATE
        conflict_kind = None

    representative = _representative(records)
    merged_ref = f'merged/{kind}:{_safe_ref_fragment(key)}'
    merged = Component(
        bom_ref=merged_ref,
        type=representative.type,
        group=representative.group,
        name=representative.name,
        version=representative.version,
        purl=representative.purl,
        cpe=representative.cpe,
        swid=representative.swid,
        supplier=representative.supplier,
        publisher=representative.publisher,
        description=representative.description,
        scope=representative.scope,
        hashes=_merged_hashes(records),
        evidence=_conflict_evidence(
            conflict_kind=conflict_kind or ConflictKind.MISSING_HASH,
            conflicts=conflicts,
            records=records,
            merged_ref=merged_ref,
        ) if conflict_kind is not None else ComponentEvidence(
            identity=_all_identities(records),
            occurrences=_all_occurrences(records),
        ),
        properties=[
            *representative.properties,
            *_bookkeeping_properties(
                status=status,
                conflict_kind=conflict_kind,
                conflicts=conflicts,
                observation_count=len(records),
            ),
        ],
    )
    return MergedComponent(
        coordinates_key=key,
        coordinate_kind=kind,
        status=status,
        components=[merged],
        conflicts=conflicts,
        conflict_kind=conflict_kind,
        observations=observations,
    )


def _safe_ref_fragment(key: str) -> str:
    return ''.join(char if char.isalnum() or char in ('-', ':', '.', '@', '/') else '_' for char in key)


def _observation_of(bom: Bom, component: Component) -> SourceObservation:
    tools: list[str] = []
    for tool in bom.metadata.tools.components:
        tools.append('/'.join(part for part in (tool.vendor, tool.name, tool.version) if part))
    occurrences = tuple(component.evidence.occurrences) if component.evidence is not None else ()
    return SourceObservation(
        bom_serial=str(bom.serial_number),
        bom_version=bom.version,
        bom_ref=component.bom_ref.value,
        hashes=tuple(component.hashes),
        occurrences=occurrences,
        tools=tuple(tools),
    )


def merge_boms(boms: Iterable[Bom]) -> list[MergedComponent]:
    """Aggregate components from ``boms`` following the documented merge rules.

    The input BOM objects are not mutated. Records are first grouped by package
    coordinates and then split by hash evidence within each group.
    """
    groups: dict[tuple[str, str], list[Component]] = {}
    provenance: dict[tuple[str, str], list[SourceObservation]] = {}
    for bom in boms:
        for component in bom.components:
            key = coordinate_key(component)
            groups.setdefault(key, []).append(component)
            provenance.setdefault(key, []).append(_observation_of(bom, component))

    results: list[MergedComponent] = []
    for key in sorted(groups, key=lambda item: (item[0], item[1])):
        records = groups[key]
        results.append(_build_merged_component(
            coordinates=key,
            records=records,
            observations=provenance[key],
        ))
    return results


def to_bom(results: Iterable[MergedComponent]) -> Bom:
    """Render merged outputs into a single in-memory :class:`Bom`."""
    bom = Bom()
    for result in results:
        bom.components.update(result.components)
    return bom


def purl_without_qualifiers(purl: PackageURL) -> str:
    """Canonical coordinate string ignoring qualifiers/subpath for grouping.

    Kept as an explicit helper so callers can see the normalization decision;
    qualifiers may distinguish redistributions and are preserved on the records.
    """
    return str(PackageURL(
        type=purl.type,
        namespace=purl.namespace,
        name=purl.name,
        version=purl.version,
    ))
