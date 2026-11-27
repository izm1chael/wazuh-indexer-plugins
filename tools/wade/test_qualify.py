# SPDX-License-Identifier: AGPL-3.0-or-later
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from qualify import step, report_status, zip_receipt, sha

class QualificationTests(unittest.TestCase):
    def test_production_never_passes_from_reference(self):
        r=report_status([{'name':'java','status':'PASS'}],False,None)
        self.assertEqual(r,{'reference':'PASS','native_package':'NOT_RUN','production':'BLOCKED','exit_code':0})
    def test_requested_build_requires_receipt(self):
        rows=[{'name':'java','status':'PASS'},{'name':'native-build','status':'PASS'}]
        self.assertEqual(report_status(rows,True,None)['exit_code'],1)
        r=report_status(rows,True,{'sha256':'x'});self.assertEqual(r['native_package'],'PASS');self.assertEqual(r['production'],'BLOCKED')
    def test_reference_failure(self):
        self.assertEqual(report_status([{'name':'java','status':'FAIL'}],False,None)['exit_code'],1)
        self.assertEqual(report_status([],False,None)['reference'],'FAIL')
    def test_actual_command_results_and_log_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);r=step(p,p,'success',[sys.executable,'-c','print("ok")'],10)
            self.assertEqual(r['status'],'PASS');self.assertEqual(r['sha256'],sha(p/r['log']))
            self.assertEqual(step(p,p,'failure',[sys.executable,'-c','raise SystemExit(3)'],10)['exit_code'],3)
            self.assertEqual(step(p,p,'missing',[str(p/'absent')],10)['status'],'FAIL')
    def test_plugin_descriptor_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'plugin.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('plugin-descriptor.properties','name=wazuh-indexer-wade\nclassname=com.wazuh.wade.plugin.WadePlugin\nversion=5.0.0\n')
            self.assertEqual(zip_receipt(p)['sha256'],sha(p))
            with zipfile.ZipFile(p,'w') as z:z.writestr('plugin-descriptor.properties','name=wrong\n')
            with self.assertRaises(ValueError):zip_receipt(p)

if __name__=='__main__':unittest.main(verbosity=2)
