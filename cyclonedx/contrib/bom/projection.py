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

"""Bom projection utilities.

Tools to derive a deployment subgraph from a full BOM
that may mix runtime and development components.
"""

__all__ = [
    'BomProjection',
    'project_bom',
]

from collections import deque
from collections.abc import Iterable
from copy import copy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Union

from ...model.bom import Bom, BomMetaData
from ...model.bom_ref import BomRef
from ...model.component import ComponentScope
from ...model.dependency import Dependency

if TYPE_CHECKING:  # pragma: no cover
    from ...model.vulnerability import BomTarget, Vulnerability


@dataclass(frozen=True)
class BomProjection:
    """
    The result of projecting a :class:`cyclonedx.model.bom.Bom`
    to the subgraph that is reachable from a set of entry refs.

    .. note::
        The projected :attr:`bom` is a new, independent object.
        The original Bom is left untouched and may still be output on its own.
    """

    #: The projected Bom, holding only reachable components, services,
    #: the dependency edges between them, and the vulnerabilities that
    #: affect them.
    bom: Bom

    #: Refs that were encountered while traversing the dependency graph
    #: (as entry refs or as ``dependsOn`` targets)
    #: but for which no component or service record exists in the original Bom.
    #: These dependencies cannot be confirmed and are reported for audit.
    missing_refs: frozenset[str] = field(default_factory=frozenset)


def project_bom(
    bom: Bom,
    entries: Iterable[Union[str, BomRef]],
    *,
    include_optional: bool = False,
) -> BomProjection:
    """
    Project a Bom to the deployment subgraph reachable from the given entry refs.

    The traversal follows :attr:`cyclonedx.model.bom.Bom.dependencies`
    starting from each of the ``entries``.
    Cycles and shared components are handled:
    every confirmed node is kept exactly once,
    together with every confirmed edge that leads to it.

    Components scoped :attr:`cyclonedx.model.component.ComponentScope.OPTIONAL`
    are treated as not deployed unless ``include_optional`` is set:
    they are dropped from the result and the traversal does not continue through them.
    A node that is reachable via both an optional and a required path
    is therefore still kept, as long as the required path is confirmed.
    Components scoped :attr:`cyclonedx.model.component.ComponentScope.EXCLUDED`
    are always treated as not deployed.

    Refs that are referenced by the graph but have no component or service
    record in the Bom cannot be confirmed.
    They are not kept in the projected graph;
    instead they are reported via :attr:`BomProjection.missing_refs`.

    Vulnerabilities are carried over if at least one of their
    ``affects`` targets is kept; their ``affects`` are narrowed
    to the kept refs. The original Bom is never modified.

    .. note::
        Only top-level components and services are projected.
        Nested components are considered for reachability,
        but are only carried over as part of a kept top-level component.

    Args:
        bom:
            The :class:`cyclonedx.model.bom.Bom` to project. Left unmodified.
        entries:
            The refs (``str`` or :class:`cyclonedx.model.bom_ref.BomRef`)
            of the entry nodes to start the traversal from -
            typically the bom-ref of the root/application component.
        include_optional:
            Whether components scoped ``optional`` are considered deployed.

    Returns:
        A :class:`BomProjection` with the projected Bom
        and the refs that could not be confirmed.
    """
    depends_on = _dependency_adjacency(bom)
    kept_refs, missing_refs = _reachable_refs(bom, depends_on, entries, include_optional)
    projected = Bom(
        metadata=bom.metadata if _metadata_is_kept(bom, kept_refs) else _metadata_without_component(bom),
        components=[c for c in bom.components if c.bom_ref.value in kept_refs],
        services=[s for s in bom.services if s.bom_ref.value in kept_refs],
        dependencies=[
            Dependency(
                ref=BomRef(ref_value),
                dependencies=(
                    Dependency(ref=BomRef(sub_ref))
                    for sub_ref in sorted(depends_on.get(ref_value, set()) & kept_refs)
                ),
            )
            for ref_value in sorted(kept_refs)
            if ref_value in depends_on
        ],
        vulnerabilities=list(_project_vulnerabilities(bom, kept_refs)),
    )
    return BomProjection(bom=projected, missing_refs=frozenset(missing_refs))


def _dependency_adjacency(bom: Bom) -> dict[str, set[str]]:
    """Map each dependency record's ref value to its ``dependsOn`` ref values."""
    depends_on: dict[str, set[str]] = {}
    for dependency in bom.dependencies:
        depends_on.setdefault(str(dependency.ref), set()).update(
            str(sub.ref) for sub in dependency.dependencies)
    return depends_on


def _reachable_refs(
    bom: Bom,
    depends_on: dict[str, set[str]],
    entries: Iterable[Union[str, BomRef]],
    include_optional: bool,
) -> tuple[set[str], set[str]]:
    """Breadth-first traversal of the dependency graph.

    Returns the kept (confirmed, deployed) ref values
    and the ref values that are missing a component/service record.
    """
    scopes: dict[str, ComponentScope] = {}
    for component in bom._get_all_components():
        value = component.bom_ref.value
        if value is not None:
            scopes[value] = component.scope or ComponentScope.REQUIRED
    known_refs = scopes.keys() | {
        service.bom_ref.value for service in bom.services
        if service.bom_ref.value is not None
    }

    def is_deployable(ref_value: str) -> bool:
        scope = scopes.get(ref_value)
        if scope is ComponentScope.EXCLUDED:
            return False
        return include_optional or scope is not ComponentScope.OPTIONAL

    kept_refs: set[str] = set()
    missing_refs: set[str] = set()
    queue = deque(str(entry) for entry in entries)
    seen: set[str] = set()
    while queue:
        ref_value = queue.popleft()
        if ref_value in seen:
            continue
        seen.add(ref_value)
        if ref_value not in known_refs:
            missing_refs.add(ref_value)
            continue
        if is_deployable(ref_value):
            kept_refs.add(ref_value)
            queue.extend(depends_on.get(ref_value, set()))
    return kept_refs, missing_refs


def _metadata_is_kept(bom: Bom, kept_refs: set[str]) -> bool:
    root = bom.metadata.component
    return root is None or root.bom_ref.value in kept_refs


def _metadata_without_component(bom: Bom) -> BomMetaData:
    metadata: BomMetaData = copy(bom.metadata)
    metadata.component = None
    return metadata


def _project_vulnerabilities(bom: Bom, kept_refs: set[str]) -> Iterable['Vulnerability']:
    for vulnerability in bom.vulnerabilities:
        kept_affects: list['BomTarget'] = [
            target for target in vulnerability.affects
            if target.ref in kept_refs
        ]
        if kept_affects:
            projected = copy(vulnerability)
            projected.affects = kept_affects
            yield projected
