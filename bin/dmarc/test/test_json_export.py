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


# set the path up one directory to match the XML validation file rua.xsd path
#sys.path[0] = os.path.join(sys.path[0], "..")


class TestDMARCprocessing(unittest.TestCase):

    def test_basic_xml_file_to_json(self):
        """Test that the DMARC.org XML example is returned correctly when processed directly in rua2json.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, None, None)
        # read in expected JSON output and compare
        json_export = "".join(d2s.process_xmlfile_to_json_lines("./data/rua.xml"))
        fjson = open("./data/rua.json.dat", "r")
        expected_result = fjson.read()
        eq(json_export, expected_result)
        fjson.close()

    def test_xml_multiple_records_file_to_json(self):
        """Test that the DMARC.org XML example is returned correctly when processed directly in rua2json.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, None, None)
        # read in expected JSON output and compare
        json_export = "".join(d2s.process_xmlfile_to_json_lines("./data/rua_multiple_records.xml"))
        fjson = open("./data/rua_multiple_records.json.dat", "r")
        expected_result = fjson.read()
        eq(json_export, expected_result)
        fjson.close()

    def test_xml_file_validated_to_json(self):
        """Test that the DMARC.org XML example is returned correctly when processed directly in rua2json.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, True, None)
        # read in expected JSON output and compare
        json_export = "".join(d2s.process_xmlfile_to_json_lines("./data/rua_multiple_records.xml"))
        fjson = open("./data/rua_multiple_records.validated.json.dat", "r")
        expected_result = fjson.read()
        eq(json_export, expected_result)
        fjson.close()

    def test_xml_file_validated_to_kv(self):
        """Test that the DMARC.org XML example is returned correctly when processed directly in rua2json.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, True, None)
        # read in expected JSON output and compare
        json_export = "".join(d2s.process_xmlfile_to_lines("./data/rua_multiple_records.xml"))
        fkv = open("./data/rua_multiple_records.validated.kv", "r")
        expected_result = fkv.read()
        eq(json_export, expected_result)
        fkv.close()

    def test_basic_xml_file_to_kv(self):
        """Test that the DMARC.org XML example is returned correctly when processed directly in rua2kv.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, None, None)
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
        fjson = open("./data/dkim2auth.json.dat", "r")
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
        """Test that the DMARC.org XML example is validated properly with the draft XSD
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        neq = self.assertNotEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, True, None)
        # read in expected XML input and validate with rua.xsd
        result = d2s.validate_xml("./data/fail_rua_xsd.xml")
        eq(result["rua_draft-dmarc-base-00-02.xsd"]["result"], "fail")
        result = d2s.validate_xml("./data/pass_rua_xsd.xml")
        eq(result["rua_draft-dmarc-base-00-02.xsd"]["result"], "pass")

    def test_google_rua_validation(self):
        """Test that the DMARC.org XML example is validated properly.
        https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, True, None)
        # read in expected XML input and validate
        result = d2s.validate_xml("./data/google_rua.xml")
        eq(result["rua_rfc7489.xsd"]["result"], "fail")
        eq(result["rua_draft-dmarc-base-00-02.xsd"]["result"], "fail")
        eq(result["rua_ta_dmarc_relaxed_v01.xsd"]["result"], "pass")

    def test_splunk_rua_validation(self):
        """Test that the Splunk RUA sample is validated properly.
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, True, None)
        # read in expected XML input and validate
        result = d2s.validate_xml("./data/splunk_rua.xml")
        eq(result["rua_rfc7489.xsd"]["result"], "fail")
        eq(result["rua_draft-dmarc-base-00-02.xsd"]["result"], "fail")
        eq(result["rua_ta_dmarc_relaxed_v01.xsd"]["result"], "pass")

    def test_aol_rua_validation(self):
        """Test that the Splunk RUA sample is validated properly.
        """
        eq = self.assertEqual
        # process basic RUA from dmarc.org
        d2s = Dir2Splunk(None, helper, None, None, None, True, None)
        # read in expected XML input and validate
        result = d2s.validate_xml("./data/aol_rua.xml")
        eq(result["rua_rfc7489.xsd"]["result"], "fail")
        eq(result["rua_draft-dmarc-base-00-02.xsd"]["result"], "fail")
        eq(result["rua_ta_dmarc_relaxed_v01.xsd"]["result"], "pass")


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
