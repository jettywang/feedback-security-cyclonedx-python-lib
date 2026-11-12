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

from cyclonedx.contrib.bom.utils import BomDependencyGraphFlatMerger, BomRefDiscriminator
from cyclonedx.exception.model import DuplicateBomRefException
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.dependency import Dependency


class TestBomRefDiscriminator(TestCase):

    def test_anonymous_refs_get_generated_values(self) -> None:
        bomref1 = BomRef()
        bomref2 = BomRef()
        self.assertIsNone(bomref1.value)
        self.assertIsNone(bomref2.value)
        with BomRefDiscriminator([bomref1, bomref2]):
            self.assertIsNotNone(bomref1.value)
            self.assertIsNotNone(bomref2.value)
            self.assertNotEqual(bomref1.value, bomref2.value, 'generated values must be unique')
        self.assertIsNone(bomref1.value)
        self.assertIsNone(bomref2.value)

    def test_explicit_values_are_kept(self) -> None:
        bomref1 = BomRef('one')
        bomref2 = BomRef('two')
        with BomRefDiscriminator([bomref1, bomref2]):
            self.assertEqual('one', bomref1.value)
            self.assertEqual('two', bomref2.value)
        self.assertEqual('one', bomref1.value)
        self.assertEqual('two', bomref2.value)

    def test_duplicate_explicit_value_is_rejected_and_not_mutated(self) -> None:
        bomref1 = BomRef('djdlkfjdslkf')
        bomref2 = BomRef('djdlkfjdslkf')
        discr = BomRefDiscriminator([bomref1, bomref2])
        with self.assertRaises(DuplicateBomRefException):
            discr.discriminate()
        # failure must not leave a half-rewritten state behind
        self.assertEqual('djdlkfjdslkf', bomref1.value)
        self.assertEqual('djdlkfjdslkf', bomref2.value)
        discr.reset()
        self.assertEqual('djdlkfjdslkf', bomref1.value)
        self.assertEqual('djdlkfjdslkf', bomref2.value)

    def test_duplicate_explicit_value_is_rejected_as_context_manager(self) -> None:
        bomref1 = BomRef('djdlkfjdslkf')
        bomref2 = BomRef('djdlkfjdslkf')
        bomref3 = BomRef()
        with self.assertRaises(DuplicateBomRefException):
            with BomRefDiscriminator([bomref1, bomref2, bomref3]):
                pass
        # even the anonymous BomRef that would have been generated stays untouched
        self.assertEqual('djdlkfjdslkf', bomref1.value)
        self.assertEqual('djdlkfjdslkf', bomref2.value)
        self.assertIsNone(bomref3.value)

    def test_same_instance_repeated_is_not_a_conflict(self) -> None:
        bomref = BomRef('shared-instance')
        with BomRefDiscriminator([bomref, bomref]):
            self.assertEqual('shared-instance', bomref.value)
        self.assertEqual('shared-instance', bomref.value)

    def test_fix_and_retry_after_conflict(self) -> None:
        bomref1 = BomRef('collide')
        bomref2 = BomRef('collide')
        discr = BomRefDiscriminator([bomref1, bomref2])
        with self.assertRaises(DuplicateBomRefException):
            discr.discriminate()
        # model is still editable: disambiguate, then a fresh discriminator succeeds
        bomref2.value = 'disambiguated'
        with BomRefDiscriminator([bomref1, bomref2]):
            self.assertEqual('collide', bomref1.value)
            self.assertEqual('disambiguated', bomref2.value)


class TestBomDependencyGraphFlatMerger(TestCase):

    def test_flatten_merge_and_reset_manually(self) -> None:
        root_bom_ref = BomRef('root_bom_ref')
        component1_bom_ref = BomRef('component1_bom_ref')
        component2_bom_ref = BomRef('component2_bom_ref')
        component3_bom_ref = BomRef('component3_bom_ref')
        component4_bom_ref = BomRef('component4_bom_ref')
        component5_bom_ref = BomRef('component5_bom_ref')
        bom = Bom(dependencies=[
            Dependency(
                root_bom_ref,
                dependencies=[
                    component1_bom_dep := Dependency(
                        component1_bom_ref,
                        dependencies=[
                            component2_bom_dep := Dependency(
                                component2_bom_ref,
                                dependencies=[
                                    component3_bom_dep := Dependency(component3_bom_ref),
                                ]
                            ),
                        ]
                    ),
                    component2_bom_dep2 := Dependency(
                        component2_bom_ref,
                        dependencies=[
                            component4_bom_dep := Dependency(component4_bom_ref),
                        ]
                    ),
                ]
            ),
            component3_bom_dep2 := Dependency(
                component3_bom_ref,
                dependencies=[
                    component4_bom_dep2 := Dependency(component4_bom_ref),
                ]
            ),
            Dependency(component5_bom_ref, (
                component1_bom_dep,
                component2_bom_dep,
                component2_bom_dep2,
                component3_bom_dep,
                component3_bom_dep2,
                component4_bom_dep,
                component4_bom_dep2,
                Dependency(root_bom_ref)
            ))
        ])
        bom_dependencies = bom.dependencies
        merger = BomDependencyGraphFlatMerger(bom)
        merger.flatten_merge()
        self.assertEqual(6, len(bom.dependencies), 'not expected len()')
        self.assertSetEqual({
            Dependency(root_bom_ref, (Dependency(component1_bom_ref), Dependency(component2_bom_ref))),
            Dependency(component1_bom_ref, (Dependency(component2_bom_ref), )),
            Dependency(component2_bom_ref, (Dependency(component3_bom_ref), Dependency(component4_bom_ref), )),
            Dependency(component3_bom_ref, (Dependency(component4_bom_ref), )),
            Dependency(component4_bom_ref),
            Dependency(component5_bom_ref, (
                Dependency(root_bom_ref),
                Dependency(component1_bom_ref),
                Dependency(component2_bom_ref),
                Dependency(component3_bom_ref),
                Dependency(component4_bom_ref),
            )),
        }, bom.dependencies)
        merger.reset()
        self.assertIs(bom_dependencies, bom.dependencies)
        self.assertSetEqual(bom_dependencies, bom.dependencies)

    def test_flatten_merge_and_reset_with(self) -> None:
        root_bom_ref = BomRef('root_bom_ref')
        component1_bom_ref = BomRef('component1_bom_ref')
        component2_bom_ref = BomRef('component2_bom_ref')
        component3_bom_ref = BomRef('component3_bom_ref')
        component4_bom_ref = BomRef('component4_bom_ref')
        component5_bom_ref = BomRef('component5_bom_ref')
        bom = Bom(dependencies=[
            Dependency(
                root_bom_ref,
                dependencies=[
                    component1_bom_dep := Dependency(
                        component1_bom_ref,
                        dependencies=[
                            component2_bom_dep := Dependency(
                                component2_bom_ref,
                                dependencies=[
                                    component3_bom_dep := Dependency(component3_bom_ref),
                                ]
                            ),
                        ]
                    ),
                    component2_bom_dep2 := Dependency(
                        component2_bom_ref,
                        dependencies=[
                            component4_bom_dep := Dependency(component4_bom_ref),
                        ]
                    ),
                ]
            ),
            component3_bom_dep2 := Dependency(
                component3_bom_ref,
                dependencies=[
                    component4_bom_dep2 := Dependency(component4_bom_ref),
                ]
            ),
            Dependency(component5_bom_ref, (
                Dependency(root_bom_ref),
                component1_bom_dep,
                component2_bom_dep,
                component2_bom_dep2,
                component3_bom_dep,
                component3_bom_dep2,
                component4_bom_dep,
                component4_bom_dep2,
            ))
        ])
        bom_dependencies = bom.dependencies
        merger = BomDependencyGraphFlatMerger(bom)
        with merger:
            self.assertEqual(6, len(bom.dependencies), 'not expected len()')
            self.assertSetEqual({
                Dependency(root_bom_ref, (Dependency(component1_bom_ref), Dependency(component2_bom_ref))),
                Dependency(component1_bom_ref, (Dependency(component2_bom_ref), )),
                Dependency(component2_bom_ref, (Dependency(component3_bom_ref), Dependency(component4_bom_ref), )),
                Dependency(component3_bom_ref, (Dependency(component4_bom_ref), )),
                Dependency(component4_bom_ref),
                Dependency(component5_bom_ref, (
                    Dependency(root_bom_ref),
                    Dependency(component1_bom_ref),
                    Dependency(component2_bom_ref),
                    Dependency(component3_bom_ref),
                    Dependency(component4_bom_ref),
                )),
            }, bom.dependencies)
        self.assertIs(bom_dependencies, bom.dependencies)
        self.assertSetEqual(bom_dependencies, bom.dependencies)
