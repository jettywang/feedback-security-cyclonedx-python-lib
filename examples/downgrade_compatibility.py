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
Example: check what a consumer on an old CycloneDX version would lose, BEFORE output.

A consumer that only reads CycloneDX 1.4 cannot receive crypto assets or full
component evidence. The old-version output still validates against the old schema -
but schema-valid does NOT mean the security information survived.

Run:  python examples/downgrade_compatibility.py
"""

from cyclonedx.exception.output import DowngradeSecurityLossException
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Copyright, Occurrence
from cyclonedx.model.crypto import AlgorithmProperties, CryptoAssetType, CryptoPrimitive, CryptoProperties
from cyclonedx.output import make_outputter
from cyclonedx.output.compatibility import check_downgrade_compatibility
from cyclonedx.schema import OutputFormat, SchemaVersion

NEW, OLD = SchemaVersion.V1_7, SchemaVersion.V1_4

# one small BOM carrying crypto asset data and component evidence
bom = Bom(components=[
    Component(
        name='acme-tls-toolkit', version='3.2.1',
        type=ComponentType.LIBRARY,
        bom_ref='pkg:generic/acme-tls-toolkit@3.2.1',
        crypto_properties=CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=AlgorithmProperties(
                primitive=CryptoPrimitive.KEM,
                parameter_set_identifier='ml-kem-768',
            ),
        ),
        evidence=ComponentEvidence(
            occurrences=[Occurrence(location='/usr/lib/libacme-tls.so.3')],
            copyright=[Copyright(text='Copyright Acme 2026')],
        ),
    ),
])

# the same BOM, rendered as new and old JSON/XML
for output_format in (OutputFormat.JSON, OutputFormat.XML):
    for version in (NEW, OLD):
        document = make_outputter(bom, output_format, version).output_as_string(indent=2)
        print(f'--- {output_format.name} {version.to_version()} ({len(document)} chars) ---')
        print(document)

# pre-output check: what actually disappears in the old version?
report = check_downgrade_compatibility(bom, OLD, source_version=NEW)
print('--- compatibility report ---')
print(report.render())

# strict option: refuse the downgrade when security-relevant content is lost
try:
    check_downgrade_compatibility(bom, OLD, source_version=NEW, strict=True)
except DowngradeSecurityLossException as e:
    print('--- strict mode refused the downgrade ---')
    print(e)
    for loss in e.report.security_losses:
        print(f'lost security content at: {loss.path}')
