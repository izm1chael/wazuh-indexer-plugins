# SPDX-License-Identifier: AGPL-3.0-or-later
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from qualify import step, report_status, zip_receipt, sha, native_test_receipt

class QualificationTests(unittest.TestCase):
    def test_production_never_passes_from_reference(self):
        r=report_status([{'name':'java','status':'PASS'}],False,None)
        self.assertEqual(r,{'reference':'PASS','native_package':'NOT_RUN','native_integration':'NOT_RUN','production':'BLOCKED','exit_code':0})
    def test_requested_build_requires_receipt(self):
        rows=[{'name':'java','status':'PASS'},{'name':'native-build','status':'PASS'}]
        self.assertEqual(report_status(rows,True,None)['exit_code'],1)
        r=report_status(rows,True,{'sha256':'x'});self.assertEqual(r['native_package'],'PASS');self.assertEqual(r['production'],'BLOCKED')
    def test_native_integration_required_and_receipt(self):
        rows=[{'name':'java','status':'PASS'},{'name':'native-build','status':'PASS'}]
        self.assertEqual(report_status(rows,True,{'sha256':'x'},True)['native_integration'],'FAIL')
        self.assertEqual(report_status(rows,True,{'sha256':'x'},True)['exit_code'],1)
        rows.append({'name':'native-integration','status':'PASS'})
        self.assertEqual(report_status(rows,True,{'sha256':'x'},True,{'sha256':'y'})['native_integration'],'PASS')
        self.assertEqual(report_status(rows,True,{'sha256':'x'},True,{'sha256':'y'})['production'],'BLOCKED')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'TEST.xml'
            fixture='<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="com.wazuh.wade.plugin.NativeTemporalRuntimeTests" name="testNativeTemporalReleaseFlow"/></testsuite>'
            p.write_text(fixture);self.assertEqual(native_test_receipt(p)['sha256'],sha(p))
            p.write_text(fixture.replace('skipped="0"','skipped="1"'))
            with self.assertRaises(ValueError):native_test_receipt(p)
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
