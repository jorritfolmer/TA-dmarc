import os
import sys
from test.test_support import run_unittest
from dmarc.dir2splunk import Dir2Splunk
import unittest
import logging as helper

# alias the logging levels to echo base_modinput.py
helper.log_debug = helper.debug
helper.log_info = helper.info
helper.log_warning = helper.warning
helper.log_error = helper.error
helper.log_critical = helper.critical


# set the path up one directory to match the XML validation file path
sys.path[0] = os.path.join(sys.path[0], "..")


class TestDMARCprocessing(unittest.TestCase):

    def test_basic_xml_file(self):
        """Test that the DMARC.org XML example is returned correctly.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, None, None)
        # read in expected JSON output and compare
        json_export = "".join(d2s.process_xmlfile_to_json_lines("./data/rua.xml"))
        fjson = open("./data/rua.json", "r")
        expected_result = fjson.read()
        eq(json_export, expected_result)
        fjson.close()
        # read in expected KV output and compare
        kv_export = "".join(d2s.process_xmlfile_to_lines("./data/rua.xml"))
        fkv = open("./data/rua.kv", "r")
        expected_result = fkv.read()
        eq(kv_export, expected_result)
        fkv.close()

    def test_multiple_dkim_auth_file(self):
        """Test that the DMARC.org XML example with multiple DKIM authentication results is returned correctly.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, None, None)
        # read in expected JSON output and compare
        json_export = "".join(d2s.process_xmlfile_to_json_lines("./data/dkim2auth.xml"))
        fjson = open("./data/dkim2auth.json", "r")
        expected_result = fjson.read()
        eq(json_export, expected_result)
        fjson.close()
        # read in expected KV output and compare
        kv_export = "".join(d2s.process_xmlfile_to_lines("./data/dkim2auth.xml"))
        fkv = open("./data/dkim2auth.kv", "r")
        expected_result = fkv.read()
        eq(kv_export, expected_result)
        fkv.close()

    def test_rua_validation(self):
        """Test that the DMARC.org XML example is validated properly.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        neq = self.assertNotEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, True, None)
        # read in expected XML input and validate
        neq(d2s.validate_xml("./data/fail_rua_xsd.xml"), True)
        eq(d2s.validate_xml("./data/pass_rua_xsd.xml"), True)


def _testclasses():
    mod = sys.modules[__name__]
    return [getattr(mod, name) for name in dir(mod) if name.startswith('Test')]


def suite():
    suite = unittest.TestSuite()
    for testclass in _testclasses():
        suite.addTest(unittest.makeSuite(testclass))
    return suite


def test_main():
    for testclass in _testclasses():
        run_unittest(testclass)


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
