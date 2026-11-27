# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest
from pathlib import Path
import subprocess
import tempfile
from dispatch import RegisteredEvaluator
from test_native import Fake
from state import RULE, Store, digest
from unittest.mock import Mock


class FeatureTests(unittest.TestCase):
    def test_causal_feature_and_risk_projection(self):
        src = Path(__file__).resolve().parent.parent/'src/com/wazuh/wade'
        test = Path(__file__).resolve().parent.parent/'test/com/wazuh/wade/FeatureHistoryTests.java'
        with tempfile.TemporaryDirectory() as out:
            subprocess.run(['javac','--release','17','-Xlint:all','-Werror','-d',out,
                            *[str(src/name) for name in ('EntityRisk.java','BehaviourBaseline.java','FeatureHistory.java')],str(test)],check=True)
            subprocess.run(['java','-cp',out,'com.wazuh.wade.FeatureHistoryTests'],check=True)


class DispatchTests(unittest.TestCase):
    def test_explicit_dispatch(self):
        fake=Fake(); store=Store(fake,'t'); job={'tenant':'t','rule_id':'r','rule_version':'1'}
        id=digest('wade-rule-revision-v1','t','r','1')
        with tempfile.TemporaryDirectory() as cp:
            d=RegisteredEvaluator(store,cp); d.count=Mock(return_value='count'); d.temporal=Mock(return_value='temporal')
            for mode, expected in [('EVENT_COUNT','count'),('DISTINCT_VALUE_COUNT','count'),('TEMPORAL_ORDERED','temporal'),('TEMPORAL_UNORDERED','temporal')]:
                fake.docs[(RULE,id)]=(0,{'tenant':'t','schema_version':1,'mode':mode})
                self.assertEqual(d(job,[],'end','as_of'),expected)
            fake.docs[(RULE,id)]=(0,{'tenant':'t','schema_version':1,'mode':'OTHER'})
            with self.assertRaises(ValueError): d(job,[],'end','as_of')
            with self.assertRaises(ValueError): d(dict(job,tenant='foreign'),[],'end','as_of')


if __name__=='__main__': unittest.main(verbosity=2)
