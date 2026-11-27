import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


def execute_canary(changes=None):
    env = {
        'PATH': os.environ.get('PATH', ''),
        'MISSION_ID': 'WOLF_CANARY_TRUTH_20261127',
        'FENCE': '7',
        'SOURCE_REPO': 'donraposo1-source/project-wolf',
        'SOURCE_SHA': 'a' * 40,
        'WORKFLOW_SHA': 'b' * 40,
        'BINDING_SHA': 'c' * 40,
        'GITHUB_SHA': 'b' * 40,
        'GITHUB_REPOSITORY': 'donraposo1-source/wolf-compute',
        'EUR_SPEND': '0',
        'COST_UNKNOWN': 'DENY',
        'PAID_FALLBACK': 'DENY',
        'TRIAL_CREDIT': 'DENY',
        'UNVERIFIED_BILLING': 'DENY',
        'UNVERIFIED_PROVIDER': 'DENY',
    }
    for key, value in (changes or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    script = ROOT / 'scripts/public-safe-canary.py'
    if script.exists():
        args = [sys.executable, str(script)]
    else:
        # Exercise the actual predecessor, so the RED run catches its constant PASS.
        workflow = (ROOT / '.github/workflows/public-safe-canary.yml').read_text()
        match = re.search(r"python3 - <<'PY'\n(.*?)\n\s*PY", workflow, re.S)
        if not match:
            raise AssertionError('No executable canary implementation')
        args = [sys.executable, '-c', textwrap.dedent(match.group(1))]
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=10)


def receipt(result):
    if result.returncode:
        raise AssertionError(result.stderr)
    lines = [line for line in result.stdout.splitlines() if line.startswith('WOLF_RESULT=')]
    if len(lines) != 1:
        raise AssertionError('Expected exactly one canary receipt')
    return json.loads(lines[0].split('=', 1)[1])


class PublicSafeCanaryTests(unittest.TestCase):
    def test_canary_does_not_certify_a_worker_or_work_product(self):
        result = receipt(execute_canary())
        self.assertEqual(result['payload']['status'], 'CANARY_ONLY')
        for field in ('inferencePerformed', 'privateSourceExecuted', 'workProductVerified'):
            self.assertIs(result['payload'][field], False)
        self.assertEqual(result['payload']['sourceAuthority'], 'DECLARED_NOT_VERIFIED')

    def test_workflow_pin_is_bound_to_executing_github_sha(self):
        result = execute_canary({'WORKFLOW_SHA': 'd' * 40})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('WOLF_RESULT=', result.stdout)

    def test_invalid_input_produces_no_receipt(self):
        for change in ({'SOURCE_SHA': 'main'}, {'BINDING_SHA': 'x' * 40},
                       {'MISSION_ID': '../../foreign'}, {'FENCE': '-1'},
                       {'FENCE': '1.5'}, {'SOURCE_REPO': 'foreign/repo'},
                       {'GITHUB_REPOSITORY': 'foreign/repo'}):
            with self.subTest(change=change):
                result = execute_canary(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('WOLF_RESULT=', result.stdout)

    def test_unknown_or_paid_economics_produce_no_receipt(self):
        for change in ({'EUR_SPEND': '1'}, {'EUR_SPEND': None},
                       {'COST_UNKNOWN': 'ALLOW'}, {'PAID_FALLBACK': 'ALLOW'},
                       {'TRIAL_CREDIT': 'ALLOW'}, {'UNVERIFIED_BILLING': None},
                       {'UNVERIFIED_PROVIDER': 'ALLOW'}):
            with self.subTest(change=change):
                result = execute_canary(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('WOLF_RESULT=', result.stdout)

    def test_digest_changes_with_each_declared_binding(self):
        original = receipt(execute_canary())['result_sha']
        for change in ({'MISSION_ID': 'WOLF_CANARY_OTHER_20261127'}, {'FENCE': '8'},
                       {'SOURCE_SHA': 'd' * 40}, {'BINDING_SHA': 'd' * 40}):
            with self.subTest(change=change):
                self.assertNotEqual(receipt(execute_canary(change))['result_sha'], original)

    def test_same_input_has_stable_receipt_digest(self):
        self.assertEqual(receipt(execute_canary())['result_sha'],
                         receipt(execute_canary())['result_sha'])


if __name__ == '__main__':
    unittest.main()
