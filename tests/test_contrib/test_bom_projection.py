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

from unittest import TestCase

from sortedcontainers import SortedSet

from cyclonedx.contrib.bom.projection import project_bom
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentScope, ComponentType
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service
from cyclonedx.model.vulnerability import BomTarget, Vulnerability
from cyclonedx.output.json import JsonV1Dot6


def _component(ref: str, scope: ComponentScope = ComponentScope.REQUIRED) -> Component:
    return Component(
        name=ref, type=ComponentType.LIBRARY,
        bom_ref=ref, scope=scope,
    )


def _dependency(ref: str, *depends_on: str) -> Dependency:
    return Dependency(
        ref=BomRef(ref),
        dependencies=[Dependency(ref=BomRef(sub)) for sub in depends_on],
    )


def _edges(bom: Bom) -> set:
    return {
        (str(dep.ref), str(sub.ref))
        for dep in bom.dependencies
        for sub in dep.dependencies
    }


def _make_bom() -> Bom:
    # graph:
    #   app -> web, db, opt(optional), cycle-a, svc, excl(excluded)
    #   web -> shared, dual, ghost(missing record)
    #   db -> shared
    #   opt -> opt-only, dual
    #   cycle-a -> cycle-b -> cycle-a
    #   dev: unreachable from app
    app = _component('app')
    bom = Bom(
        metadata=BomMetaData(component=app),
        components=[
            _component('web'),
            _component('db'),
            _component('shared'),
            _component('dual'),
            _component('opt', ComponentScope.OPTIONAL),
            _component('opt-only'),
            _component('cycle-a'),
            _component('cycle-b'),
            _component('excl', ComponentScope.EXCLUDED),
            _component('dev'),
        ],
        services=[Service(name='svc', bom_ref='svc')],
        dependencies=[
            _dependency('app', 'web', 'db', 'opt', 'cycle-a', 'svc', 'excl'),
            _dependency('web', 'shared', 'dual', 'ghost'),
            _dependency('db', 'shared'),
            _dependency('opt', 'opt-only', 'dual'),
            _dependency('cycle-a', 'cycle-b'),
            _dependency('cycle-b', 'cycle-a'),
            _dependency('dev'),
        ],
        vulnerabilities=[
            Vulnerability(id='CVE-0001', bom_ref='CVE-0001', affects=[
                BomTarget(ref='shared'), BomTarget(ref='dev'),
            ]),
            Vulnerability(id='CVE-0002', bom_ref='CVE-0002', affects=[BomTarget(ref='dev')]),
            Vulnerability(id='CVE-0003', bom_ref='CVE-0003', affects=[BomTarget(ref='opt-only')]),
        ],
    )
    return bom


class TestProjectBom(TestCase):

    def test_projection_keeps_only_reachable_deployed_subgraph(self) -> None:
        bom = _make_bom()
        projection = project_bom(bom, entries=['app', 'no-such-entry'])

        self.assertEqual(
            {'app', 'web', 'db', 'shared', 'dual', 'cycle-a', 'cycle-b', 'svc'},
            {c.bom_ref.value for c in projection.bom._get_all_components()}
            | {s.bom_ref.value for s in projection.bom.services},
        )
        # every remaining edge has both ends confirmed
        self.assertEqual({
            ('app', 'web'), ('app', 'db'), ('app', 'cycle-a'), ('app', 'svc'),
            ('web', 'shared'), ('web', 'dual'),
            ('db', 'shared'),
            ('cycle-a', 'cycle-b'), ('cycle-b', 'cycle-a'),
        }, _edges(projection.bom))
        # shared component is kept exactly once
        self.assertEqual(
            1, len([c for c in projection.bom.components if c.bom_ref.value == 'shared']))
        # unconfirmable refs are reported, not kept
        self.assertEqual(frozenset({'ghost', 'no-such-entry'}), projection.missing_refs)

    def test_projection_narrows_vulnerability_affects(self) -> None:
        bom = _make_bom()
        projection = project_bom(bom, entries=['app'])

        affects_by_id = {
            v.id: {t.ref for t in v.affects} for v in projection.bom.vulnerabilities
        }
        self.assertEqual({'CVE-0001': {'shared'}}, affects_by_id)

    def test_projection_excludes_optional_unless_requested(self) -> None:
        bom = _make_bom()
        projection = project_bom(bom, entries=['app'], include_optional=True)

        kept = {c.bom_ref.value for c in projection.bom.components}
        self.assertIn('opt', kept)
        self.assertIn('opt-only', kept)
        self.assertIn(('app', 'opt'), _edges(projection.bom))
        self.assertIn(('opt', 'opt-only'), _edges(projection.bom))
        self.assertIn(('opt', 'dual'), _edges(projection.bom))
        # 'dual' is reached via optional and required paths - kept once
        self.assertEqual(
            1, len([c for c in projection.bom.components if c.bom_ref.value == 'dual']))
        affects_by_id = {
            v.id: {t.ref for t in v.affects} for v in projection.bom.vulnerabilities
        }
        self.assertEqual(
            {'CVE-0001': {'shared'}, 'CVE-0003': {'opt-only'}}, affects_by_id)
        # excluded scope is never deployed
        self.assertNotIn('excl', kept)

    def test_projection_from_non_root_entry_drops_metadata_component(self) -> None:
        bom = _make_bom()
        projection = project_bom(bom, entries=[BomRef('web')])

        self.assertIsNone(projection.bom.metadata.component)
        self.assertEqual({'web', 'shared', 'dual'},
                         {c.bom_ref.value for c in projection.bom.components})
        self.assertEqual({('web', 'shared'), ('web', 'dual')}, _edges(projection.bom))
        self.assertEqual(frozenset({'ghost'}), projection.missing_refs)

    def test_original_bom_is_untouched_and_still_outputtable(self) -> None:
        bom = _make_bom()
        # drop the dangling edge, so the strict outputter accepts the original
        web_dep = next(d for d in bom.dependencies if str(d.ref) == 'web')
        web_dep.dependencies = SortedSet(
            d for d in web_dep.dependencies if str(d.ref) != 'ghost')
        before = JsonV1Dot6(bom).output_as_string()
        dependency_count = len(bom.dependencies)

        project_bom(bom, entries=['app'])

        self.assertEqual(10, len(bom.components))
        self.assertEqual(dependency_count, len(bom.dependencies))
        vuln1 = next(v for v in bom.vulnerabilities if v.id == 'CVE-0001')
        self.assertEqual({'shared', 'dev'}, {t.ref for t in vuln1.affects})
        self.assertIsNotNone(bom.metadata.component)
        # the original bom still serializes independently, with dev-only parts
        after = JsonV1Dot6(bom).output_as_string()
        self.assertEqual(before, after)
        self.assertIn('"dev"', after)

    def test_projected_bom_is_outputtable(self) -> None:
        bom = _make_bom()
        projection = project_bom(bom, entries=['app'])

        projected_json = JsonV1Dot6(projection.bom).output_as_string()
        self.assertIn('"shared"', projected_json)
        self.assertNotIn('"dev"', projected_json)
        self.assertNotIn('"ghost"', projected_json)
        self.assertNotIn('CVE-0002', projected_json)
