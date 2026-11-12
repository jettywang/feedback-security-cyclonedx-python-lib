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

"""Concrete in-memory BOM scenarios for the aggregation merge rules.

Run with the repository virtual environment::

    .venv/bin/python -m tools.bom_merge.demo

Everything is built from ``cyclonedx-python-lib`` model classes; nothing is
read from disk and no new package identifier is introduced.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID

from packageurl import PackageURL

from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.component_evidence import (
    AnalysisTechnique,
    ComponentEvidence,
    Identity,
    IdentityField,
    Method,
    Occurrence,
)
from cyclonedx.model.tool import Tool
from cyclonedx.output.json import JsonV1Dot6

from .merge import MergedComponent, MergeStatus, merge_boms, to_bom

# Deterministic 64-hex-char SHA-256 stand-ins, distinct per build artifact.
SHA_WIDGET_BUILD_A = '9f2c7a1d4e6b8035c2d1f7a9b4e6c80d2f5a8b1e4c7d0a3f6b9e2c5d8a1f4e7c'
SHA_WIDGET_BUILD_B = '17ab33e09c5d2f6a8b1e4c7d0a3f6b9e2c5d8a1f4e7c9f2c7a1d4e6b8035c2d1'
SHA_URLLIB3 = 'ee0b1e91d9b6f0c3a7e2d5b8f1a4c7e0d3b6a9f2c5e8b1d4a7f0c3e6b9d2a5f8'
SHA_URLLIB3_SAME = SHA_URLLIB3
SHA1_URLLIB3 = 'd8b39f2c7a1e46c0'

WIDGET_PURL = PackageURL.from_string('pkg:npm/acme%2fwidget@4.2.1')
URLLIB3_PURL = PackageURL.from_string('pkg:pypi/urllib3@2.2.1')
LODASH_PURL = PackageURL.from_string('pkg:npm/lodash@4.17.21')


def _scanner(vendor: str, name: str, version: str) -> Tool:
    return Tool(vendor=vendor, name=name, version=version)


def _bom(serial: str, version: int, tool: Tool) -> Bom:
    bom = Bom(serial_number=UUID(serial), version=version)
    bom.metadata.tools.components.add(tool)
    return bom


def build_boms() -> list[Bom]:
    """Construct the three comparison scenarios as plain in-memory BOMs."""
    source_analysis = _bom(
        'aaaaaaaa-0000-4000-8000-000000000001', 1,
        _scanner('Acme', 'source-analyzer', '3.4.0'),
    )
    binary_scan_1 = _bom(
        'bbbbbbbb-0000-4000-8000-000000000002', 1,
        _scanner('Acme', 'binary-scanner', '9.1.2'),
    )
    binary_scan_2 = _bom(
        'cccccccc-0000-4000-8000-000000000003', 1,
        _scanner('Acme', 'binary-scanner', '9.1.2'),
    )

    # Scenario 1: duplicate scans of the same artifact -> identical hashes.
    source_analysis.components.add(Component(
        bom_ref='src-widget',
        group='acme', name='widget', version='4.2.1', purl=WIDGET_PURL,
        hashes=[HashType(alg=HashAlgorithm.SHA_256, content=SHA_WIDGET_BUILD_A)],
        evidence=ComponentEvidence(identity=[Identity(
            field=IdentityField.PURL,
            confidence=Decimal('1.0'),
            concluded_value=str(WIDGET_PURL),
            methods=[Method(
                technique=AnalysisTechnique.MANIFEST_ANALYSIS,
                confidence=Decimal('1.0'),
            )],
        )]),
    ))
    binary_scan_1.components.add(Component(
        bom_ref='bin-widget',
        group='acme', name='widget', version='4.2.1', purl=WIDGET_PURL,
        hashes=[HashType(alg=HashAlgorithm.SHA_256, content=SHA_WIDGET_BUILD_A)],
        evidence=ComponentEvidence(
            identity=[Identity(
                field=IdentityField.HASH,
                confidence=Decimal('0.98'),
                concluded_value=f'SHA-256:{SHA_WIDGET_BUILD_A}',
                methods=[Method(
                    technique=AnalysisTechnique.HASH_COMPARISON,
                    confidence=Decimal('0.98'),
                )],
            )],
            occurrences=[Occurrence(location='/opt/app/node_modules/acme/widget/index.js')],
        ),
    ))

    # Scenario 2: same coordinates, different build -> different SHA-256.
    binary_scan_2.components.add(Component(
        bom_ref='bin-widget-rebuild',
        group='acme', name='widget', version='4.2.1', purl=WIDGET_PURL,
        hashes=[HashType(alg=HashAlgorithm.SHA_256, content=SHA_WIDGET_BUILD_B)],
        evidence=ComponentEvidence(
            identity=[Identity(
                field=IdentityField.HASH,
                confidence=Decimal('0.97'),
                concluded_value=f'SHA-256:{SHA_WIDGET_BUILD_B}',
                methods=[Method(
                    technique=AnalysisTechnique.HASH_COMPARISON,
                    confidence=Decimal('0.97'),
                )],
            )],
            occurrences=[Occurrence(location='/srv/app/node_modules/acme/widget/index.js')],
        ),
    ))

    # Scenario 1 continued: urllib3 observed twice, same hashes (SHA-256 + SHA-1).
    urllib3_hashes = [
        HashType(alg=HashAlgorithm.SHA_256, content=SHA_URLLIB3),
        HashType(alg=HashAlgorithm.SHA_1, content=SHA1_URLLIB3),
    ]
    source_analysis.components.add(Component(
        bom_ref='src-urllib3',
        name='urllib3', version='2.2.1', purl=URLLIB3_PURL,
        hashes=urllib3_hashes,
    ))
    binary_scan_1.components.add(Component(
        bom_ref='bin-urllib3',
        name='urllib3', version='2.2.1', purl=URLLIB3_PURL,
        hashes=[
            HashType(alg=HashAlgorithm.SHA_256, content=SHA_URLLIB3_SAME),
            HashType(alg=HashAlgorithm.SHA_1, content=SHA1_URLLIB3),
        ],
        evidence=ComponentEvidence(occurrences=[
            Occurrence(location='/usr/lib/python3.12/site-packages/urllib3/__init__.py'),
        ]),
    ))

    # Scenario 3: no hash on either record -> coordinates only, unresolved.
    source_analysis.components.add(Component(
        bom_ref='src-lodash',
        name='lodash', version='4.17.21', purl=LODASH_PURL,
        evidence=ComponentEvidence(identity=[Identity(
            field=IdentityField.PURL,
            confidence=Decimal('0.6'),
            concluded_value=str(LODASH_PURL),
            methods=[Method(
                technique=AnalysisTechnique.MANIFEST_ANALYSIS,
                confidence=Decimal('0.6'),
            )],
        )]),
    ))
    binary_scan_2.components.add(Component(
        bom_ref='bin-lodash',
        name='lodash', version='4.17.21', purl=LODASH_PURL,
        evidence=ComponentEvidence(occurrences=[
            Occurrence(location='/srv/app/node_modules/lodash/lodash.min.js'),
        ]),
    ))

    return [source_analysis, binary_scan_1, binary_scan_2]


def _print_result(result: MergedComponent) -> None:
    print(f'* coordinates ({result.coordinate_kind}): {result.coordinates_key}')
    print(f'  status: {result.status.value}')
    print(f'  observations: {len(result.observations)}')
    for observation in result.observations:
        digest = ', '.join(f'{h.alg.value}={h.content[:16]}...' for h in observation.hashes) or 'no hashes'
        print(f'    - bom {observation.bom_serial} v{observation.bom_version} '
              f'bom-ref={observation.bom_ref} [{digest}] tools={list(observation.tools)}')
    if result.conflicts:
        for conflict in result.conflicts:
            print(f'  CONFLICT {conflict.algorithm.value}:')
            for value in conflict.values:
                print(f'    - {value}')
    merged = result.components[0]
    print(f'  merged bom-ref: {merged.bom_ref.value}')
    print('  merged hashes:',
          ', '.join(f'{h.alg.value}={h.content[:16]}...' for h in merged.hashes) or 'none')
    if merged.evidence is not None and merged.evidence.identity:
        print(f'  evidence identities retained: {len(merged.evidence.identity)}')
    print()


def main() -> None:
    boms = build_boms()
    results = merge_boms(boms)
    print('=== Aggregation of source analysis + two binary scans ===\n')
    for result in results:
        _print_result(result)

    expected = {
        str(WIDGET_PURL): MergeStatus.HASH_CONFLICT,
        str(URLLIB3_PURL): MergeStatus.DUPLICATE,
        str(LODASH_PURL): MergeStatus.UNRESOLVED,
    }
    for result in results:
        assert result.status is expected[result.coordinates_key], result.coordinates_key

    outputter = JsonV1Dot6(to_bom(results))
    print('=== Merged BOM serialized as CycloneDX JSON 1.6 (first 1200 chars) ===')
    print(outputter.output_as_string()[:1200])


if __name__ == '__main__':
    main()
