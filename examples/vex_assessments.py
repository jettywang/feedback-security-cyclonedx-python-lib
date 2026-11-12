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

"""VEX example: one vulnerability assessed differently across several products.

Product A is confirmed *not affected*, product B is still *in triage*, product C is *affected*
and product D has *no evidence* yet. Because a CycloneDX ``vulnerability`` item holds a single
``analysis`` block, the differing conclusions are split into separate records, while products that
share a conclusion stay grouped under the same record's ``affects`` array.
"""

from cyclonedx.contrib.vulnerability.vex import (
    VexAffectedProduct,
    VexStatus,
    build_vex_records,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.impact_analysis import ImpactAnalysisJustification
from cyclonedx.model.vulnerability import BomTarget, BomTargetVersionRange, Vulnerability
from cyclonedx.output.json import JsonV1Dot7
from cyclonedx.output.xml import XmlV1Dot7

CVE_ID = 'CVE-2026-0001'

bom = Bom()
for ref in ('product-a', 'product-b', 'product-c', 'product-d'):
    bom.components.add(Component(name=ref, bom_ref=ref, type=ComponentType.APPLICATION))

records = build_vex_records(
    vulnerability_id=CVE_ID,
    justification=ImpactAnalysisJustification.CODE_NOT_PRESENT,
    statuses=[
        (VexStatus.NOT_AFFECTED, [
            VexAffectedProduct(ref='product-a', version_ranges=('vers:generic/lt:2.0.0',)),
        ]),
        (VexStatus.IN_TRIAGE, [
            VexAffectedProduct(ref='product-b', versions=('2.3.0',)),
        ]),
        (VexStatus.AFFECTED, [
            VexAffectedProduct(ref='product-c', versions=('5.0.0', '5.0.1')),
        ]),
    ],
)

# Missing evidence: no analysis block, only the scope the (future) assessment will apply to.
records.append(Vulnerability(
    bom_ref=f'{CVE_ID}:no-evidence',
    id=CVE_ID,
    analysis=None,
    affects=[BomTarget(ref='product-d', versions=[BomTargetVersionRange(version='9.0.0')])],
))

for record in records:
    bom.vulnerabilities.add(record)

print(JsonV1Dot7(bom).output_as_string(indent=2))
print(XmlV1Dot7(bom).output_as_string(indent=2))
