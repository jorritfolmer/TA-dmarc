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
import base64
from json import dumps
from xmljson import yahoo


# Copyright 2017-2018 Jorrit Folmer
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


class Dir2Splunk:
    """ This class:
        - parses DMARC aggregate report files in .xml, .xml.zip or .xml.gz
        - from a given directory
        - take into account which files have already been processed in KVstore
        - and writes them to Splunk as events
        - in key="value" format.
    """

    # Class variables:
    max_size        = 100000000

    def __init__(self, ew, helper, dir, quiet_secs, do_resolve, do_validate_xml, output_format, do_checkpoint=False):
        # Instance variables:
        self.helper          = helper
        self.ew              = ew
        self.dir             = dir
        self.quiet_secs      = quiet_secs
        self.do_resolve      = do_resolve
        self.do_checkpoint   = do_checkpoint
        self.do_validate_xml = do_validate_xml
        self.output_format   = output_format
        self.tmp_dir         = None

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
            if ct-mt > self.quiet_secs:
                newfileslist.append(file)
        return newfileslist

    def filter_seen_files(self, fileslist):
        """ From a given fileslist of uids, return only the ones we haven't seen before 
        based on the presence of a KVstore key.  This key uses the base64
        encoding of the filename because mongo doesn't like slashes in the key """
        seen_files = set()
        for file in fileslist:
            key = "%s" % base64.b64encode(file)
            if self.helper.get_check_point(key) is not None:
                seen_files.add(file)
        new_files = set(fileslist) - seen_files
        self.helper.log_debug('filter_seen_files: files in dir   %s' % set(fileslist))
        self.helper.log_debug('filter_seen_files: files in checkp %s' % seen_files)
        self.helper.log_debug('filter_seen_files: files new       %s' % new_files)
        return new_files

    def save_check_point(self, file):
        """ Save a filename to the KVstore with base64 encoded key because
            mongo doesn't like os.sep characters in the key
        """
        key = "%s" % base64.b64encode(file)
        value = "input=dmarc_dir, file='%s'" % file
        try:
            self.helper.save_check_point(key, value)
        except Exception as e:
            raise Exception("Error saving checkpoint data with with exception %s" % str(e))

    def rua2kv(self, xmldata, valid=False):
        """ Returns a string in kv format based on RUA XML input and its validation status,
            with optionally resolved IP addresses
        """
        mapping_meta = OrderedDict([
            ("report_metadata/org_name"          , "rpt_metadata_org_name"),
            ("report_metadata/email"             , "rpt_metadata_email"),
            ("report_metadata/extra_contact_info", "rpt_metadata_extra_contact_info"),
            ("report_metadata/report_id"         , "rpt_metadata_report_id"),
            ("report_metadata/date_range/begin"  , "rpt_metadata_date_range_begin"),
            ("report_metadata/date_range/end"    , "rpt_metadata_date_range_end"),
            ("policy_published/domain"           , "policy_published_domain"),
            ("policy_published/adkim"            , "policy_published_adkim"),
            ("policy_published/aspf"             , "policy_published_aspf"),
            ("policy_published/p"                , "policy_published_p"),
            ("policy_published/sp"               , "policy_published_sp"),
            ("policy_published/pct"              , "policy_published_pct"),
            ("policy_published/rf"               , "policy_published_rf"),
            ("policy_published/ri"               , "policy_published_ri"),
            ("policy_published/rua"              , "policy_published_rua"),
            ("policy_published/ruf"              , "policy_published_ruf"),
            ("policy_published/ro"               , "policy_published_ro"),
        ])
        mapping_record = OrderedDict([
            ("row/source_ip"                     , "row_source_ip"),
            ("row/count"                         , "row_count"),
            ("row/policy_evaluated/disposition"  , "row_policy_evaluated_disposition"),
            ("row/policy_evaluated/dkim"         , "row_policy_evaluated_dkim"),
            ("row/policy_evaluated/spf"          , "row_policy_evaluated_spf"),
            ("row/policy_evaluated/reason"       , "row_policy_evaluated_reason"),
            ("identifiers/header_from"           , "identifiers_header_from"),
            ("identifiers/envelope_to"           , "identifiers_envelope_to"),
            ("auth_results/dkim/domain"          , "auth_result_dkim_domain"),
            ("auth_results/dkim/result"          , "auth_result_dkim_result"),
            ("auth_results/dkim/human_result"    , "auth_result_dkim_human_result"),
            ("auth_results/spf/domain"           , "auth_result_spf_domain"),
            ("auth_results/spf/result"           , "auth_result_spf_result"),
        ])
        meta = ''
        for key in mapping_meta.keys():
            field = xmldata.findtext(key, default=None)
            if field is not None:
                meta += "%s=\"%s\",\n" % (mapping_meta[key], field)
        records = xmldata.findall("record")
        self.helper.log_debug("rua2kv: report_id %s has %d records"
                              % (xmldata.findtext("report_metadata/report_id", default=""), len(records)))
        result = []
        for record in records:
            data = ''
            for key in mapping_record.keys():
                field = record.findtext(key, default=None)
                if field is not None:
                    data += "%s=\"%s\",\n" % (mapping_record[key], field)
                if key == "row/source_ip" and self.do_resolve:
                    try:
                        self.helper.log_debug("rua2kv: resolving %s" % field)
                        resolve = socket.gethostbyaddr(field)
                        data += "src=\"%s\",\n" % resolve[0]
                    except Exception:
                        self.helper.log_debug("rua2kv: failed to resolve %s" % field)
            if self.do_validate_xml:
                validstring = "vendor_rua_xsd_validation=\"success\"\n" \
                    if valid else "vendor_rua_xsd_validation=\"failure\"\n"
            else:
                validstring = "vendor_rua_xsd_validation=\"unknown\"\n"
            result.append("RUA BEGIN\n" + meta + data + validstring)
        self.helper.log_debug("rua2kv: report_id %s finished parsing"
                              % xmldata.findtext("report_metadata/report_id", default=""))
        return result

    def rua2json(self, xmldata, validation_result=False):
        """ Returns a string in JSON format based on RUA XML input and its validation status,
            with optionally resolved IP addresses. Resolved checks are validated somewhat.
        """
        result = []
        result_dict = OrderedDict()
        feedback_list = []
        feedback_dict = {}
        validation_dict = {}
        required_elements = ["report_metadata", "policy_published", "record"]
        missing_elements = []
        feedback_dict["feedback"] = feedback_list

        if self.do_validate_xml:
            minimal_xsd = validation_result.pop("rua_ta_dmarc_minimal_v01.xsd")
            if minimal_xsd["result"] != "pass":
                self.helper.log_warning("rua2json: report did not contain a feedback root element")
                validation_dict["vendor_rua_xsd_validations"] = minimal_xsd
                result.append(dumps(validation_dict))
                return result
            else:
                print validation_result
                validation_dict["vendor_rua_xsd_validations"] = validation_result
        else:
            validation_dict["vendor_rua_xsd_validations"] = "None"
            pass

        # Add all elements, requiring certain elements are present
        try:
            version = xmldata.find('version')
            feedback_list.append(yahoo.data(version))
        except Exception:
            self.helper.log_debug("rua2json: report did not contain a version XML element")
        for required_element in required_elements:
            try:
                element = xmldata.find(required_element)
                feedback_list.append(yahoo.data(element))
            except Exception:
                self.helper.log_warning("rua2json: report did not contain a required XML element, %s" % required_element)
                missing_elements.append(required_element)

        if len(missing_elements):  # Return element error if any required elements are missing
            # TODO validate missing element output
            feedback_dict.clear()  # this line could be omitted, and the result could include additional information
            validation_dict["vendor_rua_missing_elements"] = missing_elements
            result.append(dumps(validation_dict))
            return result
        else:                      # Otherwise, remove the 'record' before the loop through all records
            feedback_list.pop()

        # Validation checks complete, time to add all the records

        records = xmldata.findall("record")
        self.helper.log_debug("rua2json: report_id %s has %d records"
                              % (xmldata.findtext("report_metadata/report_id", default=""), len(records)))
        for record in records:
            data_ip = record.findtext('row/source_ip')
            row_tag = record.find("row")
            if self.do_resolve:
                try:
                    self.helper.log_debug("rua2json: resolving %s" % data_ip)
                    resolve = socket.gethostbyaddr(data_ip)
                    backresolve = socket.gethostbyname_ex(resolve[0])
                    if data_ip == backresolve[2][0]:
                        ip_resolution = etree.SubElement(row_tag, "ip_resolution")
                        ip_resolution.text = resolve[0]
                except Exception:
                    self.helper.log_debug("rua2json: failed to resolve %s" % data_ip)
            feedback_list.append(yahoo.data(record))
            # Aggregate report metadata, policy, record and xsd_validation
            result_dict.update(feedback_dict)
            result_dict.update(validation_dict)
            result.append(dumps(result_dict) + "\n")
            feedback_list.pop()  # Remove record before adding next record to list
        self.helper.log_debug("rua2json: report_id %s finished parsing"
                              % xmldata.findtext("report_metadata/report_id", default=""))
        return result


    def process_zipfile(self, file):
        """ Unzip a given zip file to tmp_dir,
            return a list of extracted members, but only it they have an .xml extension,
        """
        members = []
        try:
            zf = zipfile.ZipFile(file, 'r')
        except Exception as e:
            self.helper.log_warning("process_zipfile: ignoring bad zip file %s due to %s" % (file, e))
            return members
        else:
            self.helper.log_debug("process_zipfile: extracting zip file %s to %s" % (file, self.tmp_dir))
            for member in zf.infolist():
                self.helper.log_debug("process_zipfile: contains %s of size %d (zip file %s)"
                                      % (member.filename, member.file_size, file))
                # To protect against ZIP bombs we only include XML members smaller than 100MB:
                if member.file_size < self.max_size and os.path.splitext(member.filename)[1] == ".xml":
                    extractedfile = zf.extract(member.filename, self.tmp_dir)
                    members.append(os.path.join(self.tmp_dir, extractedfile))
                    self.helper.log_debug("process_zipfile: extracted %s as %s" % (member.filename, extractedfile))
                else:
                    self.helper.log_warning("process_zipfile: skipping oversized member %s of size %d from zip file %s"
                                            % (member.filename, member.file_size, file))
            zf.close()
            self.helper.log_debug("process_zipfile: finished extracting zip file %s to %s" % (file, self.tmp_dir))
            return members

    def process_gzfile(self, file):
        """ Decompress a gz file to tmp_dir, and return a list of the extracted member """
        members = []
        with open(file, 'rb') as f:
            self.helper.log_debug("process_gzfile: extracting gz file %s" % file)
            data = f.read()
            f.close()
            zobj = zlib.decompressobj(zlib.MAX_WBITS|32)
            try:
                # Protect against gzip bombs by limiting decompression to max_size
                unz = zobj.decompress(data, self.max_size)
            except Exception as e:
                self.helper.log_warning("process_gzfile: ignoring bad gz file %s because of %s" % (file,e))
            else:
                if zobj.unconsumed_tail:
                    del data
                    del zobj
                    del unz
                    self.helper.log_warning("process_gzfile: decompression exceeded limit on file %s" % file)
                else:
                    del data
                    del zobj
                    member = os.path.join(self.tmp_dir, os.path.basename(os.path.splitext(file)[0]))
                    with open(member, "w") as m:
                        self.helper.log_debug("process_gzfile: writing to %s" % member)
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
        with open(file, 'r') as f:
            self.helper.log_debug("process_xmlfile_to_json_lines: start parsing xml file %s with do_resolve=%s" % (file, self.do_resolve))
            try:
                # To protect against various XML threats we use the parse function from defusedxml.ElementTree
                defuse_parse(f)
            except Exception as e:
                self.helper.log_warning("process_xmlfile_to_json_lines: XML parse error in file %s with exception %s"
                                        % (file, e))
            else:
                f.close()
                xmldata = parse(file)
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
        with open(file, 'r') as f:
            self.helper.log_debug("process_xmlfile_to_lines: start parsing xml file %s with do_resolve=%s"
                                  % (file, self.do_resolve))
            try:
                # To protect against various XML threats we use the parse function from defusedxml.ElementTree
                xmldata = defuse_parse(f)
            except Exception as e:
                self.helper.log_warning("process_xmlfile_to_lines: XML parse error in file %s with exception %s"
                                        % (file, e))
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
        # TODO set the filename as the source; possibly adding archive and source email information
        lines = []
        if self.output_format == "kv":
            lines = self.process_xmlfile_to_lines(file)
        elif self.output_format == "json":
            lines = self.process_xmlfile_to_json_lines(file)
        return lines


    def validate_xml(self, file):
        """ Validate DMARC XML files against an XML schema definition file (xsd)
            Returns a dict containing the XSD filename, result, and an optional informational string
        """
        dmarc_path = os.path.dirname(__file__)
        res = {}
        info = {}
        xsdfilelist = ["rua_ta_dmarc_minimal_v01.xsd",
                       "rua_ta_dmarc_relaxed_v01.xsd",
                       "rua_draft-dmarc-base-00-02.xsd",
                       "rua_rfc7489.xsd"]

        for xsdfile in xsdfilelist:
            xsdfile_long = os.path.join(dmarc_path, xsdfile)

            try:
                xmldata = open(file, 'r').read()
                xsddata = open(xsdfile_long, 'r').read()
            except Exception as e:
                self.helper.log_warning("validate_xml: xsd validation opening with %s" % str(e))
                info["result"] = "file error"
                info["info"] = "%s" % str(e)
                res[xsdfile] = info.copy()
                continue
            try:
                xml = etree.XML(xmldata)
                xsd = etree.XML(xsddata)
                xmlschema = etree.XMLSchema(xsd)
            except Exception as e:
                self.helper.log_warning("validate_xml: xml parse error for file %s with %s" % (file, str(e)))
                info["result"] = "parse error"
                info["info"] = "%s" % str(e)
                res[xsdfile] = info.copy()
                continue
            try:
                xmlschema.assertValid(xml)
            except Exception as e:
                self.helper.log_warning("validate_xml: xsd validation failed against %s for file %s with %s" % (xsdfile, file, str(e)))
                info["result"] = "fail"
                info["info"] = "%s" % str(e)
                res[xsdfile] = info.copy()
                continue
            else:
                self.helper.log_debug("validate_xml: xsd validation successful against %s for file %s" % (xsdfile, file))
                info["result"] = "pass"
                res[xsdfile] = info.copy()
        return res


    def check_dir(self):
        """ Check if self.dir is readable """
        try:
            os.listdir(self.dir)
        except Exception as e:
            raise Exception("Error: directory %s not readable with exception %s" % (self.dir, e))
        else:
            return True

    def write_event(self, lines):
        try:
            for line in lines:
                event = self.helper.new_event(line, time=None, host=None, index=self.helper.get_output_index(),
                                              source=self.helper.get_input_type(), sourcetype=self.helper.get_sourcetype(),
                                              done=True, unbroken=True)
                self.ew.write_event(event)
        except Exception as e:
            raise Exception("Exception in write_event(): %s" % e)

    def process_incoming(self):
        """ Processes the main incoming directory
        """
        self.helper.log_info("Start processing incoming directory %s with %d quiet_secs" % (self.dir, self.quiet_secs))
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
                        lines = self.process_xmlfile(xmlfile)
                        self.write_event(lines)
                elif ext == ".gz":
                    self.helper.log_info("Start processing gz file %s" % file)
                    for xmlfile in self.process_gzfile(file):
                        lines = self.process_xmlfile(xmlfile)
                        self.write_event(lines)
                elif ext == ".xml":
                    self.helper.log_info("Start processing xml file %s" % file)
                    lines = self.process_xmlfile(file)
                    self.write_event(lines)
                else:
                    self.helper.log_debug("process_incoming: Ignoring file %s" % file)
                if self.do_checkpoint:
                    self.save_check_point(file)
        finally:
            self.helper.log_info("Ended processing incoming directory %s" % self.dir)
            remove_tmp_dir(self.helper, self.tmp_dir)
            self.helper.log_debug("process_incoming: removed tmp_dir %s" % self.tmp_dir)
