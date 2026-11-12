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

from uuid import UUID

import pytest
from packageurl import PackageURL

from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.component_evidence import IdentityField
from tools.bom_merge.merge import (
    CONFLICT_PROPERTY_PREFIX,
    ConflictKind,
    MergeStatus,
    coordinate_key,
    merge_boms,
    purl_without_qualifiers,
    to_bom,
)

WIDGET_PURL_RAW = 'pkg:npm/acme%2fwidget@4.2.1'
WIDGET_PURL = 'pkg:npm/acme/widget@4.2.1'
SHA_A = '9f2c7a1d4e6b8035c2d1f7a9b4e6c80d2f5a8b1e4c7d0a3f6b9e2c5d8a1f4e7c'
SHA_B = '17ab33e09c5d2f6a8b1e4c7d0a3f6b9e2c5d8a1f4e7c9f2c7a1d4e6b8035c2d1'
SHA_C = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'


def _bom(serial: str) -> Bom:
    return Bom(serial_number=UUID(serial))


def _component(ref: str, hashes=None, *, purl=WIDGET_PURL_RAW, name='widget',
               group='acme', version='4.2.1', cpe=None) -> Component:
    return Component(
        bom_ref=ref, group=group, name=name, version=version, cpe=cpe,
        purl=PackageURL.from_string(purl) if purl else None,
        hashes=hashes or [],
    )


def _sha(value: str) -> HashType:
    return HashType(alg=HashAlgorithm.SHA_256, content=value)


def _result_map(results):
    return {result.coordinates_key: result for result in results}


def test_duplicate_scans_same_hashes_merge_into_one_instance():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('ref-a', [_sha(SHA_A)]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('ref-b', [_sha(SHA_A)]))

    result, = merge_boms([bom1, bom2])

    assert result.status is MergeStatus.DUPLICATE
    assert result.instance_count == 1
    assert result.conflicts == []
    merged = result.components[0]
    assert {h.content for h in merged.hashes} == {SHA_A}
    assert len(result.observations) == 2
    assert {obs.bom_ref for obs in result.observations} == {'ref-a', 'ref-b'}
    status_prop = next(p for p in merged.properties
                       if p.name == f'{CONFLICT_PROPERTY_PREFIX}:status')
    assert status_prop.value == 'duplicate'


def test_same_purl_different_hashes_are_distinct_instances_with_conflict():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('ref-a', [_sha(SHA_A)]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('ref-b', [_sha(SHA_B)]))

    result, = merge_boms([bom1, bom2])

    assert result.status is MergeStatus.HASH_CONFLICT
    assert result.conflict_kind is ConflictKind.HASH_MISMATCH
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.algorithm is HashAlgorithm.SHA_256
    assert conflict.values == tuple(sorted((SHA_A, SHA_B)))
    merged = result.components[0]
    assert {h.content for h in merged.hashes} == {SHA_A, SHA_B}
    hash_identities = [i for i in merged.evidence.identity
                       if i.field is IdentityField.HASH
                       and i.methods
                       and any(m.value and 'conflicting' in m.value for m in i.methods)]
    assert {i.concluded_value for i in hash_identities} == {
        f'SHA-256:{SHA_A}', f'SHA-256:{SHA_B}',
    }
    conflict_prop = next(p for p in merged.properties
                         if p.name == f'{CONFLICT_PROPERTY_PREFIX}:conflict')
    assert conflict_prop.value == 'hash-mismatch'


def test_same_algorithm_conflict_does_not_leak_other_algorithm_agreement():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('ref-a', [
        _sha(SHA_A), HashType(alg=HashAlgorithm.SHA_1, content='aa' * 20),
    ]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('ref-b', [
        _sha(SHA_B), HashType(alg=HashAlgorithm.SHA_1, content='aa' * 20),
    ]))

    result, = merge_boms([bom1, bom2])

    assert [c.algorithm for c in result.conflicts] == [HashAlgorithm.SHA_256]
    assert result.status is MergeStatus.HASH_CONFLICT


def test_missing_hash_everywhere_is_unresolved_not_a_match():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('ref-a'))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('ref-b'))

    result, = merge_boms([bom1, bom2])

    assert result.status is MergeStatus.UNRESOLVED
    assert result.conflict_kind is ConflictKind.MISSING_HASH
    assert result.components[0].hashes == set()
    purl_identity = next(i for i in result.components[0].evidence.identity
                         if i.field is IdentityField.PURL)
    assert purl_identity.methods[0].confidence == 0


def test_partial_hash_evidence_still_detects_conflict():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('ref-a', [_sha(SHA_A)]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('ref-b'))
    bom3 = _bom('33333333-3333-4333-8333-333333333333')
    bom3.components.add(_component('ref-c', [_sha(SHA_B)]))

    result, = merge_boms([bom1, bom2, bom3])

    assert result.status is MergeStatus.HASH_CONFLICT
    assert len(result.observations) == 3
    assert {h.content for h in result.components[0].hashes} == {SHA_A, SHA_B}


def test_single_record_is_status_single():
    bom = _bom('11111111-1111-4111-8111-111111111111')
    bom.components.add(_component('only', [_sha(SHA_A)]))

    result, = merge_boms([bom])

    assert result.status is MergeStatus.SINGLE
    assert result.conflict_kind is None
    assert len(result.components[0].evidence.identity) == 0


def test_bom_ref_is_never_a_merge_key():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('totally-different-ref', [_sha(SHA_A)]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('another-unrelated-ref', [_sha(SHA_A)]))

    result, = merge_boms([bom1, bom2])

    assert result.status is MergeStatus.DUPLICATE


def test_coordinate_key_precedence_and_fallbacks():
    purl_component = _component('r1')
    assert coordinate_key(purl_component) == ('purl', WIDGET_PURL)

    cpe_component = _component('r2', purl=None, cpe='cpe:2.3:a:acme:widget:4.2.1:*:*:*:*:*:*:*')
    assert coordinate_key(cpe_component) == ('cpe', 'cpe:2.3:a:acme:widget:4.2.1:*:*:*:*:*:*:*')

    gnv_component = _component('r3', purl=None, cpe=None)
    assert coordinate_key(gnv_component) == ('gnv', 'acme/widget@4.2.1')

    no_version = _component('r4', purl=None, cpe=None, version=None)
    assert coordinate_key(no_version) == ('gnv', 'acme/widget')


def test_different_coordinates_stay_in_separate_groups():
    bom = _bom('11111111-1111-4111-8111-111111111111')
    bom.components.add(_component('w', [_sha(SHA_A)]))
    bom.components.add(_component(
        'l', [_sha(SHA_C)], purl='pkg:npm/lodash@4.17.21',
        name='lodash', group=None, version='4.17.21',
    ))

    results = _result_map(merge_boms([bom]))

    assert set(results) == {WIDGET_PURL, 'pkg:npm/lodash@4.17.21'}
    assert all(r.status is MergeStatus.SINGLE for r in results.values())


def test_three_distinct_hashes_yield_three_way_conflict():
    boms = []
    for index, digest in enumerate((SHA_A, SHA_B, SHA_C), start=1):
        bom = _bom(f'00000000-0000-4000-8000-{index:012d}')
        bom.components.add(_component(f'ref-{index}', [_sha(digest)]))
        boms.append(bom)

    result, = merge_boms(boms)

    assert result.status is MergeStatus.HASH_CONFLICT
    assert result.conflicts[0].values == tuple(sorted((SHA_A, SHA_B, SHA_C)))


def test_to_bom_contains_one_component_per_group():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('a', [_sha(SHA_A)]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('b', [_sha(SHA_B)]))

    merged_bom = to_bom(merge_boms([bom1, bom2]))

    assert len(merged_bom.components) == 1


def test_purl_qualifier_normalization_helper():
    base = PackageURL.from_string('pkg:pypi/requests@2.31.0')
    with_qualifier = PackageURL.from_string('pkg:pypi/requests@2.31.0?repository_url=example.com')

    assert purl_without_qualifiers(base) == purl_without_qualifiers(with_qualifier)
    assert str(base) != str(with_qualifier)


def test_input_boms_are_not_mutated():
    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('a', [_sha(SHA_A)]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('b', [_sha(SHA_B)]))
    original_refs = {c.bom_ref.value for c in bom1.components} | \
        {c.bom_ref.value for c in bom2.components}
    original_hashes = {h.content for c in list(bom1.components) + list(bom2.components)
                       for h in c.hashes}

    merge_boms([bom1, bom2])

    assert {c.bom_ref.value for c in bom1.components} | \
        {c.bom_ref.value for c in bom2.components} == original_refs
    assert {h.content for c in list(bom1.components) + list(bom2.components)
            for h in c.hashes} == original_hashes


def test_merged_output_serializes_as_cyclonedx_json():
    import json
    import jsonschema
    from cyclonedx.output.json import JsonV1Dot6

    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('a', [_sha(SHA_A)]))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('b', [_sha(SHA_B)]))

    outputter = JsonV1Dot6(to_bom(merge_boms([bom1, bom2])))
    payload = outputter.output_as_string()

    assert SHA_A in payload and SHA_B in payload
    assert 'hash-mismatch' in payload
    assert 'hash-comparison' in payload
    instance = json.loads(payload)
    schema = json.load(open(
        'cyclonedx/schema/_res/bom-1.6.SNAPSHOT.schema.json',
        encoding='utf8',
    ))
    assert list(jsonschema.Draft7Validator(schema).iter_errors(instance)) == []
    identities = instance['components'][0]['evidence']['identity']
    assert all(
        isinstance(item['methods'][0]['confidence'], (int, float))
        and not isinstance(item['methods'][0]['confidence'], bool)
        for item in identities
    )


def test_unresolved_output_is_valid_cyclonedx_json():
    import json
    import jsonschema
    from cyclonedx.output.json import JsonV1Dot6

    bom1 = _bom('11111111-1111-4111-8111-111111111111')
    bom1.components.add(_component('a'))
    bom2 = _bom('22222222-2222-4222-8222-222222222222')
    bom2.components.add(_component('b'))

    instance = json.loads(JsonV1Dot6(to_bom(merge_boms([bom1, bom2]))).output_as_string())
    schema = json.load(open(
        'cyclonedx/schema/_res/bom-1.6.SNAPSHOT.schema.json',
        encoding='utf8',
    ))
    assert list(jsonschema.Draft7Validator(schema).iter_errors(instance)) == []


if __name__ == '__main__':  # pragma: no cover
    pytest.main([__file__, '-v'])
