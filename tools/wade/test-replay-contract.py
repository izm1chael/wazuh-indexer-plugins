# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compile the actual Java replay fixture and validate its output with Dashboard review code."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dashboard_workspace', type=Path)
    args = parser.parse_args()
    wade = Path(__file__).resolve().parent
    workspace = args.dashboard_workspace.resolve(strict=True)
    src = sorted((wade / 'src/com/wazuh/wade').glob('*.java'))
    tests = sorted((wade / 'test/com/wazuh/wade').glob('*.java'))
    with tempfile.TemporaryDirectory(prefix='wade-contract-') as temp:
        root = Path(temp)
        classes = root / 'classes'
        classes.mkdir()
        subprocess.run(['javac', '--release', '17', '-Xlint:all', '-Werror', '-d', str(classes),
                        *map(str, src + tests)], check=True, timeout=180)
        cohort = subprocess.run(['java', '-cp', str(classes), 'com.wazuh.wade.TemporalReleaseFlowTests', '--cohort'],
                                check=True, stdout=subprocess.PIPE, timeout=60).stdout
        if len(cohort) > 8 * 1024 * 1024:
            raise ValueError('unexpected cohort size')
        path = root / 'cohort.json'
        path.write_bytes(cohort)
        subprocess.run(['tsc', '--strict', '--target', 'ES2020', '--module', 'commonjs', '--lib', 'ES2020,DOM',
                        '--rootDir', str(workspace / 'public'), '--outDir', str(root / 'build'),
                        str(workspace / 'public/review.ts')], check=True, timeout=120)
        subprocess.run(['node', '-e', '''
const fs = require('node:fs');
const assert = require('node:assert/strict');
const {parseCohort, reviewCohort} = require(process.argv[1]);
const review = reviewCohort(parseCohort(fs.readFileSync(process.argv[2], 'utf8')));
assert.equal(review.status, 'REVIEW_CANDIDATE');
assert.equal(review.benign, 1);
assert.equal(review.malicious, 1);
assert.equal(review.false_positives_before, 1);
assert.equal(review.false_positives_after, 0);
assert.equal(review.unknown, 0);
assert.equal(review.malicious_regressions.length, 0);
assert.equal(review.protected_failures.length, 0);
assert.equal(review.requires_human_approval, true);
console.log('Java-to-Dashboard replay contract passed');
''', str(root / 'build/review.js'), str(path)], check=True, timeout=60)


if __name__ == '__main__':
    main()
