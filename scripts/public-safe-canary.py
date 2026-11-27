#!/usr/bin/env python3
"""Public runner diagnostic only. Never a worker or private-product attestation."""
import hashlib
import json
import os
import re
import sys


def main():
    env = os.environ
    if env.get('GITHUB_REPOSITORY') != 'donraposo1-source/wolf-compute':
        raise ValueError('CANARY_REPOSITORY_DENIED')
    if env.get('EUR_SPEND') != '0' or any(
        env.get(key) != 'DENY' for key in (
            'COST_UNKNOWN', 'PAID_FALLBACK', 'TRIAL_CREDIT',
            'UNVERIFIED_BILLING', 'UNVERIFIED_PROVIDER',
        )
    ):
        raise ValueError('CANARY_ECONOMIC_POLICY_DENIED')
    mission_id = env.get('MISSION_ID', '')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{7,127}', mission_id):
        raise ValueError('CANARY_MISSION_ID_INVALID')
    fence = env.get('FENCE', '')
    if not re.fullmatch(r'[1-9][0-9]{0,14}', fence):
        raise ValueError('CANARY_FENCE_INVALID')
    if env.get('SOURCE_REPO') != 'donraposo1-source/project-wolf':
        raise ValueError('CANARY_SOURCE_REPOSITORY_DENIED')
    for key in ('SOURCE_SHA', 'WORKFLOW_SHA', 'BINDING_SHA', 'GITHUB_SHA'):
        if not re.fullmatch(r'[a-f0-9]{40}', env.get(key, '')):
            raise ValueError('CANARY_SHA_INVALID')
    if env['WORKFLOW_SHA'] != env['GITHUB_SHA']:
        raise ValueError('CANARY_EXECUTING_SHA_MISMATCH')
    result = {
        'schema': 'WolfPublicCanary/v2',
        'mission_id': mission_id,
        'fence': int(fence),
        'source_repo': env['SOURCE_REPO'],
        'source_sha': env['SOURCE_SHA'],
        'workflow_sha': env['GITHUB_SHA'],
        'binding_sha': env['BINDING_SHA'],
        'payload': {
            'status': 'CANARY_ONLY',
            'surface': 'PUBLIC_STANDARD_RUNNER',
            'inferencePerformed': False,
            'privateSourceExecuted': False,
            'workProductVerified': False,
            'sourceAuthority': 'DECLARED_NOT_VERIFIED',
            'billingAuthority': 'NOT_A_BILLING_RECEIPT',
        },
    }
    # Bind the entire declared envelope; a constant payload hash is not provenance.
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'))
    result['result_sha'] = hashlib.sha256(raw.encode()).hexdigest()
    print('WOLF_RESULT=' + json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        # Only fixed error codes above are printed. No input/credential values.
        print(str(error), file=sys.stderr)
        sys.exit(78)
