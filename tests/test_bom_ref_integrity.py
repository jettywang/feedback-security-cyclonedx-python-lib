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
Pre-output bom-ref integrity:
  * explicit duplicate bom-refs are rejected, never silently rewritten
  * anonymous (None) bom-refs get a generated unique value
  * dependency refs and vulnerability.affects refs always resolve to a real object
  * a failed export leaves the model untouched, so it can be fixed and re-exported
"""

import json
from collections.abc import Iterable
from unittest import TestCase
from xml.etree import ElementTree

from cyclonedx.exception.model import DuplicateBomRefException, UnknownBomRefException
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service
from cyclonedx.model.vulnerability import BomTarget, Vulnerability
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.output.xml import XmlV1Dot6
from cyclonedx.schema import SchemaVersion

SV = SchemaVersion.V1_6


def _build_cross_reference_bom() -> tuple[Bom, Component, Component, Component, Service, Vulnerability]:
    """A small BOM that wires services, components, dependencies and vulnerability.affects together."""
    bom = Bom()
    root = Component(name='app', type=ComponentType.APPLICATION, bom_ref='ref-app')
    library = Component(name='lib-x', type=ComponentType.LIBRARY, bom_ref='ref-lib')
    anonymous = Component(name='lib-anon', type=ComponentType.LIBRARY)  # no explicit bom-ref
    service = Service(name='svc-y', bom_ref='ref-svc')
    vulnerability = Vulnerability(
        id='CVE-2026-0001', bom_ref='ref-vuln',
        affects=[BomTarget(ref='ref-lib'), BomTarget(ref='ref-svc')])

    bom.metadata.component = root
    bom.components.add(library)
    bom.components.add(anonymous)
    bom.services.add(service)
    bom.vulnerabilities.add(vulnerability)
    bom.register_dependency(root, [library, anonymous, service])
    bom.register_dependency(library, [anonymous])
    return bom, root, library, anonymous, service, vulnerability


class _JsonRefView:
    def __init__(self, document: dict) -> None:
        self._doc = document

    def declared_refs(self) -> set[str]:
        refs = {c['bom-ref'] for c in self._doc.get('components', [])}
        refs |= {s['bom-ref'] for s in self._doc.get('services', [])}
        refs |= {v['bom-ref'] for v in self._doc.get('vulnerabilities', [])}
        metadata_component = self._doc.get('metadata', {}).get('component')
        if metadata_component is not None:
            refs.add(metadata_component['bom-ref'])
        return refs

    def dependency_refs(self) -> tuple[set[str], set[str]]:
        owners: set[str] = set()
        depends_on: set[str] = set()
        for dependency in self._doc.get('dependencies', []):
            owners.add(dependency['ref'])
            depends_on.update(dependency.get('dependsOn', []))
        return owners, depends_on

    def affect_refs(self) -> set[str]:
        return {
            target['ref']
            for vulnerability in self._doc.get('vulnerabilities', [])
            for target in vulnerability.get('affects', [])
        }


class _XmlRefView:
    def __init__(self, document: ElementTree.Element) -> None:
        self._doc = document

    def _iter(self, tag: str) -> Iterable[ElementTree.Element]:
        return (e for e in self._doc.iter() if e.tag.rsplit('}', 1)[-1] == tag)

    def declared_refs(self) -> set[str]:
        refs = {e.attrib['bom-ref'] for e in self._iter('component')}
        refs |= {e.attrib['bom-ref'] for e in self._iter('service')}
        refs |= {e.attrib['bom-ref'] for e in self._iter('vulnerability')}
        return refs

    def dependency_refs(self) -> tuple[set[str], set[str]]:
        owners: set[str] = set()
        depends_on: set[str] = set()
        for dependency in self._iter('dependency'):
            owners.add(dependency.attrib['ref'])
            depends_on.update(child.attrib['ref'] for child in dependency)
        return owners, depends_on

    def affect_refs(self) -> set[str]:
        return {e.text for e in self._iter('ref') if e.text is not None}


class TestCrossReferenceIntegrity(TestCase):

    def _assert_all_refs_unique_and_resolvable(self, declared: set[str], dependency_owners: set[str],
                                               dependency_targets: set[str], affects: set[str]) -> None:
        # every declared bom-ref is unique (set built from the actual serialized entries)
        self.assertIn('ref-app', declared)
        self.assertIn('ref-lib', declared)
        self.assertIn('ref-svc', declared)
        self.assertIn('ref-vuln', declared)
        # every dependency owner / target points at an existing component or service
        self.assertTrue(dependency_owners <= declared, f'unknown dependency owner: {dependency_owners - declared}')
        self.assertTrue(dependency_targets <= declared,
                        f'unknown dependency target: {dependency_targets - declared}')
        # every vulnerability.affects target points at an existing component or service
        self.assertEqual({'ref-lib', 'ref-svc'}, affects)
        self.assertTrue(affects <= declared, f'unknown affects target: {affects - declared}')

    def test_json_refs_are_unique_and_point_at_real_objects(self) -> None:
        bom, root, library, anonymous, service, vulnerability = _build_cross_reference_bom()
        output = JsonV1Dot6(bom).output_as_string()
        view = _JsonRefView(json.loads(output))

        declared = view.declared_refs()
        # the anonymous component received a generated bom-ref and it is unique
        generated = anonymous.bom_ref.value
        self.assertIsNone(generated, 'discriminator state must be restored after export')
        generated_refs = declared - {'ref-app', 'ref-lib', 'ref-svc', 'ref-vuln'}
        self.assertEqual(1, len(generated_refs))
        self.assertTrue(next(iter(generated_refs)).startswith('BomRef'))

        owners, targets = view.dependency_refs()
        self._assert_all_refs_unique_and_resolvable(declared, owners, targets, view.affect_refs())
        # the generated ref is the one used by the dependency graph, not a second random value
        generated_ref = next(iter(generated_refs))
        self.assertIn(generated_ref, owners)
        self.assertIn(generated_ref, targets)

    def test_xml_refs_are_unique_and_point_at_real_objects(self) -> None:
        bom, root, library, anonymous, service, vulnerability = _build_cross_reference_bom()
        output = XmlV1Dot6(bom).output_as_string()
        view = _XmlRefView(ElementTree.fromstring(output))

        declared = view.declared_refs()
        generated_refs = declared - {'ref-app', 'ref-lib', 'ref-svc', 'ref-vuln'}
        self.assertEqual(1, len(generated_refs))
        self.assertTrue(next(iter(generated_refs)).startswith('BomRef'))

        owners, targets = view.dependency_refs()
        self._assert_all_refs_unique_and_resolvable(declared, owners, targets, view.affect_refs())
        generated_ref = next(iter(generated_refs))
        self.assertIn(generated_ref, owners)
        self.assertIn(generated_ref, targets)

    def test_duplicate_component_bom_ref_is_rejected_for_json_and_xml(self) -> None:
        bom = Bom()
        first = Component(name='first', type=ComponentType.LIBRARY, bom_ref='shared-ref')
        second = Component(name='second', type=ComponentType.LIBRARY, bom_ref='shared-ref')
        bom.components.add(first)
        bom.components.add(second)

        for outputter in (JsonV1Dot6(bom), XmlV1Dot6(bom)):
            with self.subTest(outputter=outputter.output_format):
                with self.assertRaises(DuplicateBomRefException):
                    outputter.output_as_string()

        # neither object was rewritten: the model is still editable
        self.assertEqual('shared-ref', first.bom_ref.value)
        self.assertEqual('shared-ref', second.bom_ref.value)
        second.bom_ref.value = 'disambiguated-ref'
        # same model instance now exports cleanly in both formats
        JsonV1Dot6(bom).output_as_string()
        XmlV1Dot6(bom).output_as_string()

    def test_component_and_service_sharing_bom_ref_is_rejected(self) -> None:
        bom = Bom()
        component = Component(name='comp', type=ComponentType.LIBRARY, bom_ref='cross-object')
        service = Service(name='svc', bom_ref='cross-object')
        bom.components.add(component)
        bom.services.add(service)

        with self.assertRaises(DuplicateBomRefException):
            JsonV1Dot6(bom).output_as_string()
        self.assertEqual('cross-object', component.bom_ref.value)
        self.assertEqual('cross-object', service.bom_ref.value)

    def test_dangling_affects_ref_is_rejected(self) -> None:
        bom = Bom()
        component = Component(name='comp', type=ComponentType.LIBRARY, bom_ref='real-comp')
        bom.components.add(component)
        bom.vulnerabilities.add(Vulnerability(
            id='CVE-2026-0002', bom_ref='ref-vuln-2',
            affects=[BomTarget(ref='real-comp'), BomTarget(ref='ghost')]))

        for outputter in (JsonV1Dot6(bom), XmlV1Dot6(bom)):
            with self.subTest(outputter=outputter.output_format):
                with self.assertRaises(UnknownBomRefException):
                    outputter.output_as_string()

        # fix the dangling target and re-export
        vulnerability = next(iter(bom.vulnerabilities))
        next(iter(vulnerability.affects)).ref = 'real-comp'
        for target in vulnerability.affects:
            if target.ref == 'ghost':
                target.ref = 'real-comp'
        JsonV1Dot6(bom).output_as_string()
        XmlV1Dot6(bom).output_as_string()

    def test_failed_export_leaves_no_partial_rewrite_and_is_retryable(self) -> None:
        bom, root, library, anonymous, service, vulnerability = _build_cross_reference_bom()
        # introduce a collision after an otherwise valid model was built; use the metadata
        # component so the vulnerability.affects targets stay resolvable
        root.bom_ref.value = 'ref-lib'

        json_outputter = JsonV1Dot6(bom)
        with self.assertRaises(DuplicateBomRefException):
            json_outputter.output_as_string()
        self.assertFalse(json_outputter.generated, 'failed export must not be marked generated')

        # explicit values unchanged and the anonymous component is still anonymous
        self.assertEqual('ref-lib', library.bom_ref.value)
        self.assertEqual('ref-lib', root.bom_ref.value)
        self.assertIsNone(anonymous.bom_ref.value)

        # repair and retry through the very same outputter instance
        root.bom_ref.value = 'ref-app'
        output = json_outputter.output_as_string()
        self.assertTrue(json_outputter.generated)
        view = _JsonRefView(json.loads(output))
        declared = view.declared_refs()
        owners, targets = view.dependency_refs()
        self.assertTrue(owners <= declared and targets <= declared)
        self.assertTrue(view.affect_refs() <= declared)

    def test_repeated_same_bom_ref_instance_is_allowed(self) -> None:
        shared = BomRef('same-instance-ref')
        bom = Bom()
        bom.components.add(Component(name='comp', type=ComponentType.LIBRARY, bom_ref=shared))
        # dependency graph referencing the very same BomRef instance must not be seen as a conflict
        bom.dependencies = [Dependency(shared)]
        output = JsonV1Dot6(bom).output_as_string()
        self.assertIn('same-instance-ref', output)
