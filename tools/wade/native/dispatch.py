# SPDX-License-Identifier: AGPL-3.0-or-later
"""Explicit mode dispatch for the qualification runner; not production authorization."""
from evaluator import RegisteredCountEvaluator
from temporal import RegisteredTemporalEvaluator, MODES
from state import RULE, digest


class RegisteredEvaluator:
    def __init__(self, store, classpath, *, timeout=10):
        self.store = store
        self.count = RegisteredCountEvaluator(store, classpath, timeout=timeout)
        self.temporal = RegisteredTemporalEvaluator(store, classpath, timeout=timeout)

    def __call__(self, job, rows, end, as_of):
        if job.get('tenant') != self.store.tenant:
            raise ValueError('foreign job scope')
        id = digest('wade-rule-revision-v1', self.store.tenant, job['rule_id'], job['rule_version'])
        mode = self.store._read(RULE, id)['_source']['mode']
        if mode in ('EVENT_COUNT', 'DISTINCT_VALUE_COUNT'):
            return self.count(job, rows, end, as_of)
        if mode in MODES:
            return self.temporal(job, rows, end, as_of)
        raise ValueError('unsupported evaluation mode')
