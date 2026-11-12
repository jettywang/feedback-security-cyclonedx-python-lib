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
# Copyright (c) OWASP Foundation. All Rights Reserved.


"""
Pre-output downgrade compatibility check.

Older CycloneDX schema versions cannot express everything the current model can hold
(e.g. cryptographic assets and component evidence require >= 1.6 / >= 1.5).
Downgrading silently drops that content — and a document that *validates* against an
older schema still does **not** prove the security information survived intact.

This module compares the actual serialized content of a :class:`cyclonedx.model.bom.Bom`
at two schema versions and reports exactly which objects and fields disappear,
so callers can decide up front whether a downgrade is acceptable — or refuse it.
"""

from dataclasses import dataclass, field
from enum import Enum, unique
from json import loads as json_loads
from typing import TYPE_CHECKING, Any, Optional

from ..contrib.bom.utils import BomDependencyGraphFlatMerger, BomRefDiscriminator
from ..exception.output import DowngradeSecurityLossException
from ..schema import SchemaVersion
from ..schema.schema import SCHEMA_VERSIONS

if TYPE_CHECKING:  # pragma: no cover
    from ..model.bom import Bom

#: Path segments whose loss is considered security-relevant.
SECURITY_SENSITIVE_KEYS = frozenset({
    'cryptoProperties',
    'evidence',
    'hashes',
    'vulnerabilities',
    'signature',
    'pedigree',
})


@unique
class LossKind(Enum):
    """What kind of content is affected by a downgrade."""

    OBJECT = 'object'  #: a whole object or list (with everything below it) disappears
    FIELD = 'field'  #: a single field disappears
    VALUE = 'value'  #: a field survives, but its value changes


@dataclass(frozen=True)
class LostContent:
    """A single piece of content that does not survive the downgrade."""

    path: str  #: location in the document, e.g. ``components[0].cryptoProperties``
    kind: LossKind
    security_relevant: bool
    detail: str = ''  #: short preview of the lost/changed content


@dataclass(frozen=True)
class CompatibilityReport:
    """Result of a downgrade compatibility check."""

    source_version: SchemaVersion
    target_version: SchemaVersion
    losses: tuple[LostContent, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """Whether the downgrade is lossless."""
        return not self.losses

    @property
    def security_losses(self) -> tuple[LostContent, ...]:
        """The subset of losses that is security-relevant."""
        return tuple(loss for loss in self.losses if loss.security_relevant)

    def render(self) -> str:
        """Human-readable, locatable listing of everything that disappears."""
        if self.ok:
            return (
                f'Downgrade {self.source_version.to_version()}'
                f' -> {self.target_version.to_version()} is lossless.'
            )
        lines = [
            f'Downgrade {self.source_version.to_version()}'
            f' -> {self.target_version.to_version()} loses content:',
        ]
        lines += [
            f'  - [{loss.kind.value}]{" [security]" if loss.security_relevant else ""}'
            f' {loss.path}{f" ({loss.detail})" if loss.detail else ""}'
            for loss in self.losses
        ]
        return '\n'.join(lines)


def _normalized_bom_dict(bom: 'Bom', schema_version: SchemaVersion) -> dict[str, Any]:
    """Serialize ``bom`` exactly as the given schema version would, and return the raw data."""
    view = SCHEMA_VERSIONS.get(schema_version)
    if view is None:
        raise ValueError(f'Unknown schema_version: {schema_version!r}')
    bom.validate()
    with BomRefDiscriminator.from_bom(bom):
        with BomDependencyGraphFlatMerger(bom):
            bom_data: dict[str, Any] = json_loads(
                bom.as_json(  # type:ignore[attr-defined]
                    view_=view))
    return bom_data


def _preview(value: Any, max_len: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= max_len else f'{text[:max_len]}...'


def _is_security_path(path: str) -> bool:
    segments = (segment.split('[')[0] for segment in path.split('.'))
    return any(segment in SECURITY_SENSITIVE_KEYS for segment in segments)


def _diff(source: Any, target: Any, path: str, losses: list[LostContent]) -> None:
    if isinstance(source, dict) and isinstance(target, dict):
        for key, source_value in source.items():
            child_path = f'{path}.{key}' if path else key
            if key not in target:
                losses.append(LostContent(
                    path=child_path,
                    kind=LossKind.OBJECT if isinstance(source_value, (dict, list)) else LossKind.FIELD,
                    security_relevant=_is_security_path(child_path),
                    detail=_preview(source_value),
                ))
            else:
                _diff(source_value, target[key], child_path, losses)
    elif isinstance(source, list) and isinstance(target, list):
        for index, source_item in enumerate(source):
            child_path = f'{path}[{index}]'
            if index >= len(target):
                losses.append(LostContent(
                    path=child_path,
                    kind=LossKind.OBJECT,
                    security_relevant=_is_security_path(child_path),
                    detail=_preview(source_item),
                ))
            else:
                _diff(source_item, target[index], child_path, losses)
    elif source != target:
        losses.append(LostContent(
            path=path,
            kind=LossKind.VALUE,
            security_relevant=_is_security_path(path),
            detail=f'{_preview(source)} becomes {_preview(target)}',
        ))


def check_downgrade_compatibility(
    bom: 'Bom',
    target_version: SchemaVersion,
    *,
    source_version: Optional[SchemaVersion] = None,
    strict: bool = False,
) -> CompatibilityReport:
    """
    Check which content of ``bom`` is lost when output at ``target_version``
    instead of ``source_version`` (defaults to the latest known schema version).

    The comparison is content-based: the BOM is serialized at both versions and the
    results are diffed. Passing the older schema's validation is *not* treated as
    proof that security information survived.

    Default output behavior is untouched — this is an opt-in, non-blocking check.
    With ``strict=True``, a :class:`cyclonedx.exception.output.DowngradeSecurityLossException`
    carrying the report is raised if any security-relevant content would be lost.

    :param bom: the BOM to check
    :param target_version: the (older) schema version the consumer requires
    :param source_version: the version the model is expressed in (default: latest)
    :param strict: refuse the downgrade on security-relevant loss
    :return: CompatibilityReport
    """
    if source_version is None:
        source_version = max(SchemaVersion)
    if target_version > source_version:
        raise ValueError(
            f'target_version {target_version.to_version()} is newer than'
            f' source_version {source_version.to_version()} - nothing to downgrade.')
    source_data = _normalized_bom_dict(bom, source_version)
    target_data = _normalized_bom_dict(bom, target_version)
    losses: list[LostContent] = []
    _diff(source_data, target_data, '', losses)
    report = CompatibilityReport(
        source_version=source_version,
        target_version=target_version,
        losses=tuple(losses),
    )
    if strict and report.security_losses:
        raise DowngradeSecurityLossException(report)
    return report
