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
from warnings import warn

from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.exception.output import DowngradeSecurityLossException
from cyclonedx.exception.serialization import SerializationOfUnsupportedComponentTypeException
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Copyright, Occurrence
from cyclonedx.output import make_outputter
from cyclonedx.output.compatibility import (
    CompatibilityReport,
    LossKind,
    check_downgrade_compatibility,
)
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.validation.xml import XmlValidator
from tests._data.models import get_crypto_properties_algorithm

NEW = SchemaVersion.V1_7
OLD = SchemaVersion.V1_4


def make_small_bom() -> Bom:
    """One small BOM carrying crypto asset data and component evidence."""
    return Bom(components=[
        Component(
            name='acme-tls-toolkit', version='3.2.1',
            type=ComponentType.LIBRARY,
            bom_ref='pkg:generic/acme-tls-toolkit@3.2.1',
            crypto_properties=get_crypto_properties_algorithm(),
            evidence=ComponentEvidence(
                occurrences=[Occurrence(location='/usr/lib/libacme-tls.so.3')],
                copyright=[Copyright(text='Copyright Acme 2026')],
            ),
        ),
    ])


class TestDowngradeCompatibilityCheck(TestCase):

    def test_old_outputs_are_schema_valid_but_incomplete(self) -> None:
        """Schema-valid old-version output must NOT be mistaken for complete security info."""
        bom = make_small_bom()
        for output_format in (OutputFormat.JSON, OutputFormat.XML):
            new_out = make_outputter(bom, output_format, NEW).output_as_string()
            old_out = make_outputter(bom, output_format, OLD).output_as_string()
            # the old output validates fine against the old schema...
            validator: object
            if output_format is OutputFormat.JSON:
                validator = JsonStrictValidator(OLD)
            else:
                validator = XmlValidator(OLD)
            try:
                errors = validator.validate_str(old_out)  # type:ignore[attr-defined]
            except MissingOptionalDependencyException:
                warn('!!! skipped schema validation', category=UserWarning, stacklevel=0)
            else:
                self.assertIsNone(errors, old_out)
            # ...yet the security content is silently gone
            self.assertNotIn('cryptoProperties', old_out)
            self.assertNotIn('occurrences', old_out)
            self.assertIn('cryptoProperties', new_out)
            self.assertIn('occurrences', new_out)

    def test_report_lists_actually_lost_objects_and_fields(self) -> None:
        report = check_downgrade_compatibility(make_small_bom(), OLD)
        self.assertIsInstance(report, CompatibilityReport)
        self.assertFalse(report.ok)
        lost_paths = {loss.path for loss in report.losses}
        self.assertIn('components[0].cryptoProperties', lost_paths)
        self.assertIn('components[0].evidence.occurrences', lost_paths)
        crypto_loss = next(loss for loss in report.losses
                           if loss.path == 'components[0].cryptoProperties')
        self.assertIs(crypto_loss.kind, LossKind.OBJECT)
        self.assertTrue(crypto_loss.security_relevant)
        # every loss is locatable and rendered
        rendered = report.render()
        self.assertIn('components[0].cryptoProperties', rendered)
        self.assertIn('components[0].evidence.occurrences', rendered)
        self.assertIn('1.7 -> 1.4', rendered)

    def test_security_losses_are_flagged(self) -> None:
        report = check_downgrade_compatibility(make_small_bom(), OLD)
        security_paths = {loss.path for loss in report.security_losses}
        self.assertIn('components[0].cryptoProperties', security_paths)
        self.assertIn('components[0].evidence.occurrences', security_paths)
        self.assertTrue(all(loss.security_relevant for loss in report.security_losses))

    def test_strict_mode_refuses_security_loss_with_locatable_result(self) -> None:
        with self.assertRaises(DowngradeSecurityLossException) as ctx:
            check_downgrade_compatibility(make_small_bom(), OLD, strict=True)
        report = ctx.exception.report
        self.assertFalse(report.ok)
        message = str(ctx.exception)
        self.assertIn('components[0].cryptoProperties', message)
        self.assertIn('components[0].evidence.occurrences', message)

    def test_default_is_non_blocking_and_compatible_output_stays_compatible(self) -> None:
        bom = Bom(components=[
            Component(name='acme-lib', version='1.0', type=ComponentType.LIBRARY),
        ])
        # default: returns a report instead of raising
        report = check_downgrade_compatibility(bom, OLD)
        self.assertEqual((), report.security_losses)
        # strict only refuses on security-relevant loss
        strict_report = check_downgrade_compatibility(bom, OLD, strict=True)
        self.assertEqual((), strict_report.security_losses)

    def test_same_version_is_lossless(self) -> None:
        report = check_downgrade_compatibility(make_small_bom(), NEW)
        self.assertTrue(report.ok)
        self.assertIn('lossless', report.render())

    def test_upgrade_target_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            check_downgrade_compatibility(
                make_small_bom(), NEW, source_version=OLD)

    def test_unsupported_component_type_fails_loudly_not_silently(self) -> None:
        """A cryptographic-asset component type cannot even be serialized for old versions."""
        bom = Bom(components=[
            Component(name='my-algo', version='1.0',
                      type=ComponentType.CRYPTOGRAPHIC_ASSET,
                      crypto_properties=get_crypto_properties_algorithm()),
        ])
        with self.assertRaises(SerializationOfUnsupportedComponentTypeException):
            check_downgrade_compatibility(bom, OLD)
