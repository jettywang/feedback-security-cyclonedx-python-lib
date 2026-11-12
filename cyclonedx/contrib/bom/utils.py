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

"""Bom related utilities"""

__all__ = [
    'BomRefDiscriminator',
    'BomDependencyGraphFlatMerger',
]

from collections.abc import Iterable
from itertools import chain
from random import random
from typing import TYPE_CHECKING, Any

from ...exception.model import DuplicateBomRefException
from ...model.dependency import Dependency

if TYPE_CHECKING:  # pragma: no cover
    from ...model.bom import Bom
    from ...model.bom_ref import BomRef


class BomRefDiscriminator:
    """
    Ensure that a collection of BomRef objects
    has unique, non‑empty :attr:`cyclonedx.model.bom_ref.BomRef.value`.

    A new value is **generated** for (and only for) BomRefs whose ``value`` is ``None``,
    i.e. anonymous objects that never got an explicit identifier assigned.

    A conflict is **rejected** with :class:`DuplicateBomRefException` when two *distinct*
    BomRef objects carry the same non‑empty explicit ``value``. Such a collision means two
    different objects would be indistinguishable in the serialized BOM, so any reference
    (dependency graph entries, ``vulnerability.affects`` targets ...) pointing at that
    value could no longer be resolved to a single object. The caller must disambiguate the
    model itself; silently rewriting an explicit value would corrupt those references.
    Repeated occurrences of the very same BomRef instance are not a conflict.

    All original values are preserved and can be restored via :meth:`reset()`
    or by using this class as a context manager. Validation happens before any BomRef is
    mutated, so a raised conflict leaves every BomRef (and therefore the whole model)
    untouched and still editable.
    """

    def __init__(self, bomrefs: Iterable['BomRef'], prefix: str = 'BomRef') -> None:
        # NOTE: do not use dict/set here, different BomRefs with same value
        #       have same hash and would shadow each other.
        self._bomrefs = tuple((bomref, bomref.value) for bomref in bomrefs)
        self._prefix = prefix

    def __enter__(self) -> None:
        self.discriminate()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.reset()

    def discriminate(self) -> None:
        """
        Enforce uniqueness across all
        :attr:`cyclonedx.model.bom_ref.BomRef.value`s.

        A newly generated unique identifier is assigned to BomRefs whose ``value`` is
        ``None``. Distinct BomRefs sharing an explicit, non‑empty ``value`` cause a
        :class:`DuplicateBomRefException`; no BomRef is modified in that case, so the
        model remains in its original, editable state.
        """
        # Pass 1: detect explicit conflicts before mutating anything, so a failure never
        # leaves the model in a half-rewritten state.
        explicit_owner: dict[str, 'BomRef'] = {}
        for bomref, _ in self._bomrefs:
            value = bomref.value
            if value is None:
                continue
            owner = explicit_owner.get(value)
            if owner is not None and owner is not bomref:
                raise DuplicateBomRefException(
                    f'Duplicate bom-ref {value!r} is used by multiple distinct objects; '
                    'assign unique bom-ref values before exporting the Bom.')
            explicit_owner[value] = bomref

        # Pass 2: only anonymous BomRefs receive generated identifiers.
        known_values = set(explicit_owner)
        for bomref, _ in self._bomrefs:
            if bomref.value is None:
                value = self._make_unique(known_values)
                bomref.value = value
                known_values.add(value)

    def reset(self) -> None:
        """
        Restore all :attr:`cyclonedx.model.bom_ref.BomRef.value`s to
        their original state.
        """
        for bomref, original_value in self._bomrefs:
            bomref.value = original_value

    def _make_unique(self, known_values: Iterable[str] = ()) -> str:
        candidate = f'{self._prefix}{str(random())[1:]}{str(random())[1:]}'  # nosec B311
        while candidate in known_values:
            candidate = f'{self._prefix}{str(random())[1:]}{str(random())[1:]}'  # nosec B311
        return candidate

    @classmethod
    def from_bom(cls, bom: 'Bom', prefix: str = 'BomRef') -> 'BomRefDiscriminator':
        """
        Create a discriminator for all :class:`cyclonedx.model.bom_ref.BomRefs`
        contained within a Bom.

        This includes BomRefs from
          * :attr:`cyclonedx.model.bom.Bom.components`
          * :attr:`cyclonedx.model.bom.Bom.services`
          * :attr:`cyclonedx.model.bom.Bom.vulnerabilities`
        """
        return cls(chain(
            (c.bom_ref for c in bom._get_all_components()),
            (s.bom_ref for s in bom.services),
            (v.bom_ref for v in bom.vulnerabilities),
        ), prefix)


class BomDependencyGraphFlatMerger:
    """
    Context‑manager utility that temporarily flattens and merges all
    :attr:`cyclonedx.model.bom.Bom.dependencies`.

    When used as a context manager, the :class:`cyclonedx.model.bom.Bom`'s
    dependency graph is replaced with a flattened, merged representation
    for the duration of the ``with`` block and automatically restored
    afterward.
    """

    def __init__(self, bom: 'Bom') -> None:
        self._bom = bom
        # NOTE: do not use the getter - see `reset()` for reasons.
        self._deps = self._bom._dependencies

    def __enter__(self) -> None:
        self.flatten_merge()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.reset()

    def flatten_merge(self) -> None:
        """
        Flatten and merge all :attr:`cyclonedx.model.bom.Bom.dependencies`.

        This produces a non‑recursive, merged representation of the entire
        dependency graph and assigns it to the Bom.

        .. note::
           The original dependency graph is not modified. A new, flattened
           dependency structure is assigned to the Bom.
        """
        self._bom.dependencies = self._flatten_merge(self._deps)

    def reset(self) -> None:
        """
        Restore the :class:`cyclonedx.model.bom.Bom`'s dependency graph to
        its original state.

        .. note::
           This does not modify the dependency graph. It simply reassigns
           the original dependency collection back to the Bom.
        """
        # NOTE: not using the setter, which would create overhead,
        #       and - most importantly - this could cause deduplication of an existing malformed set.
        #       Just access the internal field directly!
        self._bom._dependencies = self._deps

    @staticmethod
    def _flatten_merge(deps: Iterable[Dependency]) -> Iterable[Dependency]:
        flat: dict['BomRef', list['BomRef']] = {}
        todos = list(deps)
        seen = set()
        while todos:
            todo = todos.pop()
            if (todo_id := id(todo)) in seen:
                continue
            seen.add(todo_id)
            ds = flat.setdefault(todo.ref, [])
            if todo_deps := todo.dependencies:
                ds.extend(d.ref for d in todo_deps)
                todos.extend(todo_deps)
        return (
            Dependency(br, (Dependency(d) for d in ds))
            for br, ds
            in flat.items()
        )
