from builtins import str
from past.builtins import basestring
from builtins import object
import os
import sys
import time
import socket
from lxml import etree
from defusedxml.ElementTree import parse as defuse_parse
from defusedxml.lxml import parse
import zipfile
import zlib
from collections import OrderedDict
from dmarc.helper import create_tmp_dir
from dmarc.helper import remove_tmp_dir
from dmarc.autodetectxmlencoding import autoDetectXMLEncoding
import base64
from json import dumps
from xmljson import yahoo


# Copyright 2017-2020 Jorrit Folmer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


class Dir2Splunk(object):
    """ This class:
        - parses DMARC aggregate report files in .xml, .xml.zip or .xml.gz
        - from a given directory
        - take into account which files have already been processed in KVstore
        - and writes them to Splunk as events
        - in key="value" format.
    """

    # Class variables:
    max_size = 100000000
    max_files = 100

    def __init__(
            self,
            ew,
            helper,
            dir,
            quiet_secs,
            do_resolve,
            do_validate_xml,
            output_format,
            do_checkpoint=False):
        # Instance variables:
        self.helper = helper
        self.ew = ew
        self.dir = dir
        self.quiet_secs = quiet_secs
        self.do_resolve = do_resolve
        self.do_checkpoint = do_checkpoint
        self.do_validate_xml = do_validate_xml
        self.output_format = output_format
        self.tmp_dir = None
        self.source_filename = ""

    def myfsencode(self, file):
        ''' Given a filename
            Return the byte version of it, depending on the Python version '''
        if sys.version_info[0] < 3:
            return(file)
        else:
            return(os.fsencode(file))

    def list_incoming(self):
        """ Returns a list of files for the incoming directory """
        newfileslist = []
        try:
            fileslist = os.listdir(self.dir)
        except Exception:
            raise Exception("Path does not exist: %s" % self.dir)
        for shortfile in fileslist:
            file = os.path.join(self.dir, shortfile)
            if os.path.isfile(file):
                newfileslist.append(file)
        return newfileslist

    def filter_quiet_files(self, fileslist):
        """ Filters fileslist for files that have modtime > quiet_secs """
        newfileslist = []
        for file in fileslist:
            try:
                mt = os.stat(file).st_mtime
            except Exception:
                raise ValueError("Cannot determine modtime of %s" % file)
            ct = time.time()
            if ct - mt > self.quiet_secs:
                newfileslist.append(file)
        return newfileslist

    def filter_seen_files(self, fileslist):
        """ From a given fileslist of uids, return only the ones we haven't seen before
        based on the presence of a KVstore key.  This key uses the base64
        encoding of the filename because mongo doesn't like slashes in the key """
        seen_files = set()
        for file in fileslist:
            key = "%s" % base64.b64encode(self.myfsencode(file))
            if self.helper.get_check_point(key) is not None:
                seen_files.add(file)
        new_files = set(fileslist) - seen_files
        self.helper.log_debug(
            'filter_seen_files: files in dir   %s' %
            set(fileslist))
        self.helper.log_debug(
            'filter_seen_files: files in checkp %s' %
            seen_files)
        self.helper.log_debug(
            'filter_seen_files: files new       %s' %
            new_files)
        return new_files

    def save_check_point(self, file):
        """ Save a filename to the KVstore with base64 encoded key because
            mongo doesn't like os.sep characters in the key
        """
        key = "%s" % base64.b64encode(self.myfsencode(file))
        value = "input=dmarc_dir, file='%s'" % file
        try:
            self.helper.save_check_point(key, value)
        except Exception as e:
            raise Exception(
                "Error saving checkpoint data with with exception %s" %
                str(e))

    def rua2kv(self, xmldata, valid=False):
        """ Returns a string in kv format based on RUA XML input and its validation status,
            with optionally resolved IP addresses
        """
        mapping_meta = OrderedDict([
            ("report_metadata/org_name", "rpt_metadata_org_name"),
            ("report_metadata/email", "rpt_metadata_email"),
            ("report_metadata/extra_contact_info", "rpt_metadata_extra_contact_info"),
            ("report_metadata/report_id", "rpt_metadata_report_id"),
            ("report_metadata/date_range/begin", "rpt_metadata_date_range_begin"),
            ("report_metadata/date_range/end", "rpt_metadata_date_range_end"),
            ("policy_published/domain", "policy_published_domain"),
            ("policy_published/adkim", "policy_published_adkim"),
            ("policy_published/aspf", "policy_published_aspf"),
            ("policy_published/p", "policy_published_p"),
            ("policy_published/sp", "policy_published_sp"),
            ("policy_published/pct", "policy_published_pct"),
            ("policy_published/rf", "policy_published_rf"),
            ("policy_published/ri", "policy_published_ri"),
            ("policy_published/rua", "policy_published_rua"),
            ("policy_published/ruf", "policy_published_ruf"),
            ("policy_published/ro", "policy_published_ro"),
        ])
        mapping_record = OrderedDict([
            ("row/source_ip", "row_source_ip"),
            ("row/count", "row_count"),
            ("row/policy_evaluated/disposition", "row_policy_evaluated_disposition"),
            ("row/policy_evaluated/dkim", "row_policy_evaluated_dkim"),
            ("row/policy_evaluated/spf", "row_policy_evaluated_spf"),
            ("row/policy_evaluated/reason", "row_policy_evaluated_reason"),
            ("identifiers/header_from", "identifiers_header_from"),
            ("identifiers/envelope_to", "identifiers_envelope_to"),
            ("auth_results/dkim/domain", "auth_result_dkim_domain"),
            ("auth_results/dkim/result", "auth_result_dkim_result"),
            ("auth_results/dkim/human_result", "auth_result_dkim_human_result"),
            ("auth_results/spf/domain", "auth_result_spf_domain"),
            ("auth_results/spf/result", "auth_result_spf_result"),
            ("auth_results/spf/scope", "auth_result_spf_scope"),
        ])
        meta = ''
        for key in list(mapping_meta.keys()):
            field = xmldata.findtext(key, default=None)
            if field is not None:
                meta += "%s=\"%s\",\n" % (mapping_meta[key], field.lower()) if key.startswith(
                    'policy') else "%s=\"%s\",\n" % (mapping_meta[key], field)
        records = xmldata.findall("record")
        self.helper.log_debug(
            "rua2kv: report_id %s has %d records" %
            (xmldata.findtext(
                "report_metadata/report_id",
                default=""),
                len(records)))
        result = []
        for record in records:
            data = ''
            for key in list(mapping_record.keys()):
                field = record.findtext(key, default=None)
                if field is not None:
                    data += "%s=\"%s\",\n" % (
                        mapping_record[key], field.lower())
                if key == "row/source_ip" and self.do_resolve:
                    try:
                        self.helper.log_debug("rua2kv: resolving %s" % field)
                        resolve = socket.gethostbyaddr(field)
                        data += "src=\"%s\",\n" % resolve[0]
                    except Exception:
                        self.helper.log_debug(
                            "rua2kv: failed to resolve %s" % field)
            if self.do_validate_xml:
                validstring = "vendor_rua_xsd_validation=\"success\"\n" \
                    if valid["rua_ta_dmarc_relaxed_v01.xsd"]['result'] == "pass" \
                    else "vendor_rua_xsd_validation=\"failure\"\n"
            else:
                validstring = "vendor_rua_xsd_validation=\"unknown\"\n"
            result.append("RUA BEGIN\n" + meta + data + validstring)
        self.helper.log_debug(
            "rua2kv: report_id %s finished parsing" %
            xmldata.findtext(
                "report_metadata/report_id",
                default=""))
        return result

    def dict2lower(self, obj):
        """ Make dictionary lowercase
            Copyright 2016 by vldbnc, MIT license
            https://stackoverflow.com/questions/764235/dictionary-to-lowercase-in-python """
        if isinstance(obj, dict):
            t = type(obj)()
            for k, v in list(obj.items()):
                t[k.lower()] = self.dict2lower(v)
            return t
        elif isinstance(obj, (list, set, tuple)):
            t = type(obj)
            return t(self.dict2lower(o) for o in obj)
        elif isinstance(obj, basestring):
            return obj.lower()
        else:
            return obj

    def rua2json(self, xmldata, validation_result=[]):
        """ Returns a string in JSON format based on RUA XML input and its validation results
            with optionally resolved IP addresses. Resolved checks are validated somewhat.
        """
        # Setup result dict structures
        result = []
        result_dict = OrderedDict()
        feedback_list = []
        feedback_dict = {}
        feedback_dict["feedback"] = feedback_list
        validation_dict = {}
        if self.do_validate_xml:
            validation_dict["vendor_rua_xsd_validations"] = validation_result
        else:
            validation_dict["vendor_rua_xsd_validations"] = "None"
        # Get metadata elements from aggregate report
        meta_elements = ["report_metadata", "policy_published", "version"]
        for meta_element in meta_elements:
            try:
                element = yahoo.data(xmldata.find(meta_element))
            except Exception:
                self.helper.log_debug(
                    "rua2json: report did not contain metadata element, %s" %
                    meta_element)
            else:
                if meta_element == 'policy_published':
                    # convert keys and values to lowercasr
                    element = self.dict2lower(element)
                    feedback_list.append(element)
                else:
                    feedback_list.append(element)
        records = xmldata.findall("record")
        self.helper.log_debug(
            "rua2json: report_id %s has %d records" %
            (xmldata.findtext(
                "report_metadata/report_id",
                default=""),
                len(records)))
        # Get individual records from aggregate report
        for record in records:
            data_ip = record.findtext('row/source_ip')
            row_tag = record.find("row")
            record = yahoo.data(record)
            record = self.dict2lower(record)
            if self.do_resolve:
                try:
                    self.helper.log_debug("rua2json: resolving %s" % data_ip)
                    resolve = socket.gethostbyaddr(data_ip)
                except Exception:
                    self.helper.log_debug(
                        "rua2json: failed to resolve %s" % data_ip)
                else:
                    try:
                        self.helper.log_debug(
                            "rua2json: backresolving %s" % resolve[0])
                        backresolve = socket.gethostbyname_ex(resolve[0])
                    except Exception:
                        self.helper.log_debug(
                            "rua2json: backresolving failed for %s" %
                            resolve[0])
                    else:
                        if data_ip == backresolve[2][0]:
                            # Add resolved ip to row
                            self.helper.log_debug(
                                "rua2json: backresolving success: %s resolves to %s and back" %
                                (data_ip, resolve[0]))
                            record["record"]["row"]["ip_resolution"] = resolve[0]
                        else:
                            self.helper.log_debug(
                                "rua2json: backresolving failed: %s does NOT resolve to %s and back" %
                                (data_ip, resolve[0]))
            feedback_list.append(record)
            # Aggregate report metadata, policy, record and xsd_validation
            result_dict.update(feedback_dict)
            result_dict.update(validation_dict)
            result.append(dumps(result_dict) + "\n")
            feedback_list.pop()  # Remove record before adding next record to list
        self.helper.log_debug(
            "rua2json: report_id %s finished parsing" %
            xmldata.findtext(
                "report_metadata/report_id",
                default=""))
        return result

    def process_zipfile(self, file):
        """ Unzip a given zip file to tmp_dir,
            return a list of extracted members, but only it they have an .xml extension,
        """
        members = []
        try:
            zf = zipfile.ZipFile(file, 'r')
        except Exception as e:
            self.helper.log_warning(
                "process_zipfile: ignoring bad zip file %s due to %s" %
                (file, e))
            return members
        else:
            self.helper.log_debug(
                "process_zipfile: extracting zip file %s to %s" %
                (file, self.tmp_dir))
            for member in zf.infolist():
                self.helper.log_debug(
                    "process_zipfile: contains %s of size %d (zip file %s)" %
                    (member.filename, member.file_size, file))
                # To protect against ZIP bombs we only include XML members
                # smaller than 100MB:
                if member.file_size < self.max_size and member.filename.endswith(
                        "xml"):
                    extractedfile = zf.extract(member.filename, self.tmp_dir)
                    members.append(os.path.join(self.tmp_dir, extractedfile))
                    self.helper.log_debug(
                        "process_zipfile: extracted %s as %s" %
                        (member.filename, extractedfile))
                elif member.file_size >= self.max_size and member.filename.endswith("xml"):
                    self.helper.log_warning(
                        "process_zipfile: skipping oversized member %s of size %d from zip file %s" %
                        (member.filename, member.file_size, file))
                else:
                    self.helper.log_debug(
                        "process_zipfile: skipping non-XML ,ember %s of size %d from zip file %s" %
                        (member.filename, member.file_size, file))
            zf.close()
            self.helper.log_debug(
                "process_zipfile: finished extracting zip file %s to %s" %
                (file, self.tmp_dir))
            return members

    def process_gzfile(self, file):
        """ Decompress a gz file to tmp_dir, and return a list of the extracted member """
        members = []
        with open(file, 'rb') as f:
            self.helper.log_debug(
                "process_gzfile: extracting gz file %s" %
                file)
            data = f.read()
            f.close()
            zobj = zlib.decompressobj(zlib.MAX_WBITS | 32)
            try:
                # Protect against gzip bombs by limiting decompression to
                # max_size
                unz = zobj.decompress(data, self.max_size)
            except Exception as e:
                self.helper.log_warning(
                    "process_gzfile: ignoring bad gz file %s because of %s" %
                    (file, e))
            else:
                if zobj.unconsumed_tail:
                    del data
                    del zobj
                    del unz
                    self.helper.log_warning(
                        "process_gzfile: decompression exceeded limit on file %s" %
                        file)
                else:
                    del data
                    del zobj
                    member = os.path.join(
                        self.tmp_dir, os.path.basename(
                            os.path.splitext(file)[0]))
                    with open(member, "wb") as m:
                        self.helper.log_debug(
                            "process_gzfile: writing to %s" % member)
                        m.write(unz)
                        m.close()
                        del unz
                        m.close()
                        members.append(member)
        return members

    def process_xmlfile_to_json_lines(self, file):
        """ Processes an XML from from a given directory,
            and returns a list of string lines in JSON format
        """
        lines = []
        with open(file, 'rb') as f:
            self.helper.log_debug(
                "process_xmlfile_to_json_lines: start parsing xml file %s with do_resolve=%s" %
                (file, self.do_resolve))
            try:
                # To protect against various XML threats we first use the parse
                # function from defusedxml.ElementTree
                xmldata = defuse_parse(f)
            except Exception as e:
                self.helper.log_warning(
                    "process_xmlfile_to_json_lines: XML parse error in file %s with exception %s" %
                    (file, e))
            else:
                f.close()
                if self.do_validate_xml:
                    res = self.validate_xml(file)
                    lines = self.rua2json(xmldata, res)
                else:
                    lines = self.rua2json(xmldata)
                del xmldata
        return lines

    def process_xmlfile_to_lines(self, file):
        """ Processes an XML from from a given directory,
            and return a list of string lines in key=value format
        """
        lines = []
        with open(file, 'rb') as f:
            self.helper.log_debug(
                "process_xmlfile_to_lines: start parsing xml file %s with do_resolve=%s" %
                (file, self.do_resolve))
            try:
                # To protect against various XML threats we use the parse
                # function from defusedxml.ElementTree
                xmldata = defuse_parse(f)
            except Exception as e:
                self.helper.log_warning(
                    "process_xmlfile_to_lines: XML parse error in file %s with exception %s" %
                    (file, e))
            else:
                f.close()
                if self.do_validate_xml:
                    res = self.validate_xml(file)
                    lines = self.rua2kv(xmldata, res)
                else:
                    lines = self.rua2kv(xmldata)
                del xmldata
        return lines

    def process_xmlfile(self, file):
        """ Wrapper function to process an XML file based on self.output_format """
        self.source_filename = os.path.basename(file)
        lines = []
        if self.output_format == "kv":
            lines = self.process_xmlfile_to_lines(file)
        elif self.output_format == "json":
            lines = self.process_xmlfile_to_json_lines(file)
        else:
            self.helper.log_warning(
                "process_xmlfile: invalid output_format %s",
                self.output_format)
        return lines

    def validate_xml_xsd(self, file, xsdfile):
        """ Validate DMARC XML files against an XML schema definition file (xsd)
            Returns a dict containing the result (bool), and an optional informational string
        """
        dmarc_path = os.path.dirname(__file__)
        info = {}

        xsdfile_long = os.path.join(dmarc_path, xsdfile)

        # Read XML and XSD files
        try:
            xmldata = open(file, 'rb').read()
            xsddata = open(xsdfile_long, 'rb').read()
        except Exception as e:
            self.helper.log_warning(
                "validate_xml_xsd: error opening with %s" %
                str(e))
            info["result"] = "fail"
            info["info"] = "%s" % str(e)
            return info
        # Parse the XML and XSD
        try:
            xml = etree.XML(xmldata)
            xsd = etree.XML(xsddata)
            xmlschema = etree.XMLSchema(xsd)
        except Exception as e:
            self.helper.log_warning(
                "validate_xml_xsd: xml parse error for file %s with %s" %
                (file, str(e)))
            info["result"] = "fail"
            info["info"] = "%s" % str(e)
            return info
        # Validate XML against XSD
        try:
            xmlschema.assertValid(xml)
        except Exception as e:
            self.helper.log_debug(
                "validate_xml_xsd: xsd validation failed against %s for file %s with %s" %
                (xsdfile, file, str(e)))
            info["result"] = "fail"
            info["info"] = "%s" % str(e)
            return info
        else:
            self.helper.log_debug(
                "validate_xml_xsd: xsd validation successful against %s for file %s" %
                (xsdfile, file))
            info["result"] = "pass"
            return info

    def is_valid_rua_xmlfile(self, file):
        """ Perform some sanity checks on a RUA XML file:
            - is it free from XML threats?
            - does it look like an aggregate report?
            Returns True if valid, False if invalid """
        # To protect against various XML threats we use the parse function from
        # defusedxml.ElementTree
        with open(file, 'rb') as f:
            self.helper.log_debug(
                "is_valid_rua_xmlfile: start parsing xml file %s" %
                file)
            try:
                xmldata = defuse_parse(f)
            except Exception as e:
                self.helper.log_warning(
                    "is_valid_rua_xmlfile: XML parse error in file %s with exception %s" %
                    (file, e))
                f.close()
                return False
            # Does it look like an aggregate report?
            res = self.validate_xml_xsd(file, "rua_ta_dmarc_minimal_v01.xsd")
            if res["result"] != "pass":
                return False
            # Does it have the necessary elements?
            required_elements = [
                "report_metadata",
                "policy_published",
                "record"]
            for required_element in required_elements:
                try:
                    element = xmldata.find(required_element)
                except Exception:
                    self.helper.log_warning(
                        "is_valid_rua_xmlfile: report did not contain a required XML element, %s" %
                        required_element)
                    return False
            return True
        return False

    def fix_xml_encoding(self, file):
        """ Check encoding of provided (xml) file, and transcode if necessary to work around
            limited Splunk encoding support
            Returns the path of the transcoded file in the tmp dir """
        with open(file, 'rb') as f:
            try:
                # Determine xml encoding
                xmldata = f.read()
                encoding = autoDetectXMLEncoding(xmldata)
            except Exception as e:
                self.helper.log_warning(
                    "fix_xml_encoding: file %s charset cannot be determined with exception %s" %
                    (file, str(e)))
                return file
            self.helper.log_debug(
                "fix_xml_encoding: file %s has encoding %s" %
                (file, encoding))
            # Only convert it if it differs from the ones already supported by
            # Splunk's libxml2
            if encoding.lower() == 'utf_8' or encoding.lower() == 'utf-8':
                return file
            elif encoding.lower() == 'utf_16_be' or encoding.lower() == 'utf_16_le':
                return file
            elif encoding.lower() == 'iso-8859-1':
                return file
            elif encoding.lower() == 'ascii':
                return file
            else:
                self.helper.log_debug(
                    "fix_xml_encoding: encoding %s in utf-8" % file)
                try:
                    xmldata = xmldata.decode(encoding).encode('utf-8')
                    xmldata = xmldata.replace(" encoding=\"" + encoding + "\"", "")
                except Exception as e:
                    self.helper.log_warning(
                        "fix_xml_encoding: file %s charset cannot be converted with exception %s" %
                        (file, str(e)))
                    return file
                newfile = os.path.join(
                    self.tmp_dir, "transcoded_" + os.path.basename(file))
                with open(newfile, "wb") as nf:
                    self.helper.log_debug(
                        "fix_xml_encoding: writing to %s" % newfile)
                    nf.write(xmldata)
                    return newfile
                return file

    def validate_xml(self, file):
        """ Main XML validation function for DMARC XML files
            Returns a dict containing the validations result (bool), and an optional informational string
        """
        # Validate XML against various RUA XSDs
        xsdfilelist = ["rua_ta_dmarc_relaxed_v01.xsd",
                       "rua_draft-dmarc-base-00-02.xsd",
                       "rua_rfc7489.xsd"]
        res = {}
        for xsdfile in xsdfilelist:
            tmp = self.validate_xml_xsd(file, xsdfile)
            res[xsdfile] = tmp.copy()
        # Placeholder for future string checks
        return res

    def check_dir(self):
        """ Check if self.dir is readable """
        try:
            os.listdir(self.dir)
        except Exception as e:
            raise Exception(
                "Error: directory %s not readable with exception %s" %
                (self.dir, e))
        else:
            return True

    def write_event(self, lines):
        # TODO set the filename as the source; possibly adding archive and
        # source email information
        try:
            for line in lines:
                event = self.helper.new_event(
                    line,
                    time=None,
                    host=None,
                    index=self.helper.get_output_index(),
                    source=self.source_filename,
                    sourcetype=self.helper.get_sourcetype(),
                    done=True,
                    unbroken=True)
                self.ew.write_event(event)
        except Exception as e:
            raise Exception("Exception in write_event(): %s" % e)

    def process_incoming(self):
        """ Processes the main incoming directory
        """
        self.helper.log_info(
            "Start processing incoming directory %s with %d quiet_secs" %
            (self.dir, self.quiet_secs))
        try:
            self.check_dir()
            self.tmp_dir = create_tmp_dir(self.helper)
            fileslist = self.filter_quiet_files(self.list_incoming())
            if self.do_checkpoint:
                fileslist = self.filter_seen_files(fileslist)
            for file in fileslist:
                ext = os.path.splitext(file)[1]
                if ext == ".zip":
                    self.helper.log_info("Start processing zip file %s" % file)
                    for xmlfile in self.process_zipfile(file):
                        xmlfile = self.fix_xml_encoding(xmlfile)
                        if self.is_valid_rua_xmlfile(xmlfile):
                            lines = self.process_xmlfile(xmlfile)
                            self.write_event(lines)
                        else:
                            self.helper.log_debug(
                                "process_incoming: ignoring invalid xml file %s from %s" %
                                (xmlfile, file))
                elif ext == ".gz":
                    self.helper.log_info("Start processing gz file %s" % file)
                    for xmlfile in self.process_gzfile(file):
                        xmlfile = self.fix_xml_encoding(xmlfile)
                        if self.is_valid_rua_xmlfile(xmlfile):
                            lines = self.process_xmlfile(xmlfile)
                            self.write_event(lines)
                        else:
                            self.helper.log_debug(
                                "process_incoming: ignoring invalid xml file %s from %s" %
                                (xmlfile, file))
                elif ext == ".xml":
                    self.helper.log_info("Start processing xml file %s" % file)
                    file = self.fix_xml_encoding(file)
                    if self.is_valid_rua_xmlfile(file):
                        lines = self.process_xmlfile(file)
                        self.write_event(lines)
                    else:
                        self.helper.log_debug(
                            "process_incoming: ignoring invalid xml file %s" % file)
                else:
                    self.helper.log_debug(
                        "process_incoming: Ignoring file %s" % file)
                if self.do_checkpoint:
                    self.save_check_point(file)
        finally:
            self.helper.log_info(
                "Ended processing incoming directory %s" %
                self.dir)
            remove_tmp_dir(self.helper, self.tmp_dir)
            self.helper.log_debug(
                "process_incoming: removed tmp_dir %s" %
                self.tmp_dir)
