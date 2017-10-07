import os
import sys
import time
import datetime
import socket
from defusedxml.ElementTree import parse
import zipfile
import zlib
import shutil
import errno
from collections import OrderedDict

# #################################################################
# Class for processing DMARC RUA files in .xml, .xml.zip or .xml.gz
# #################################################################

# Copyright 2017 Jorrit Folmer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions: #

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.  #

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

class Dmarc:

    # Class variables:
    tmp_dir         = "tmp"
    done_dir        = "done"
    bad_dir         = "bad"
    max_size        = 100000000

    def __init__(self, ew, helper, dir, quiet_secs, do_resolve):
        # Instance variables:
        self.helper     = helper
        self.ew         = ew
        self.dir        = dir
        self.do_resolve = do_resolve
        self.quiet_secs = quiet_secs

    def list_incoming(self):
        """ Returns a list of files for the incoming directory """
        newfileslist=[]
        try:
            fileslist = os.listdir(self.dir)
        except Exception as e:
            raise Exception("Path does not exist: %s" % self.dir)
        for shortfile in fileslist:
            file = os.path.join(self.dir,shortfile)
            if os.path.isfile(file):
                newfileslist.append(file)
        return newfileslist

    def filter_quiet_files(self, fileslist):
        """ Filters fileslist for files that have modtime > quiet_secs """
        newfileslist=[]
        for file in fileslist:
            try:
                mt = os.stat(file).st_mtime
            except Exception as e:
                raise ValueError("Cannot determine modtime of %s" % file)
            ct = time.time()
            if ct-mt > self.quiet_secs:
                newfileslist.append(file)
        return newfileslist

    def rua2kv(self, xmldata):
	""" Returns a string in kv format based on RUA XML input, with
            optionally resolved IP addresses  
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
            ("identifiers/header_from"           , "identifiers_header_from"),
            ("auth_results/dkim/domain"          , "auth_result_dkim_domain"),
            ("auth_results/dkim/result"          , "auth_result_dkim_result"),
            ("auth_results/spf/domain"           , "auth_result_spf_domain"),
            ("auth_results/spf/result"           , "auth_result_spf_result"),
        ])
        meta = ''
        for key in mapping_meta.keys():
            field = xmldata.findtext(key, default=None)
            if field != None:
                meta += "%s=\"%s\",\n" % (mapping_meta[key], field)
        records = xmldata.findall("record")
        self.helper.log_info("    - report_id %s has %d records" % (xmldata.findtext("report_metadata/report_id", default=""), len(records)))
        result = []
        for record in records:
            data = ''
            for key in mapping_record.keys():
                field = record.findtext(key, default=None)
                if field != None:
                    data += "%s=\"%s\",\n" % (mapping_record[key], field)
                if key == "row/source_ip" and self.do_resolve:
                    try:
                        resolve = socket.gethostbyaddr(field)
                        data += "src=\"%s\",\n" % resolve[0]
                    except Exception:
                        pass
            result.append("RUA BEGIN\n" + meta + data)
        return result

    def process_zipfile(self, file):
        """ Unzip a given zip file, move any member in it to tmp_dir/,
            return a list of extracted members, but only it they have an .xml extension,
            and move the zip file to done_dir
        """
        members = []
        try:
            zf = zipfile.ZipFile(file, 'r')
        except Exception, e:
            self.helper.log_info("    - moving bad zip file %s to bad_dir due to %s" % (file, e))
            dest = os.path.join(self.dir,self.bad_dir,os.path.basename(file))
            try:
                shutil.move(file,dest)
            except Exception, e:
                self.helper.log_error("    - error moving %s to bad_dir with exception %s" % (file, e))
            return members
        else:
            self.helper.log_info("    - extracting zip file %s" % file)
            for member in zf.infolist():
                self.helper.log_info("    - contains %s of size %d (zip file %s)" % (member.filename, member.file_size, file))
                # Protect against ZIP bombs we only include members smaller than 100MB:
                if member.file_size < self.max_size:
                    zf.extract(member.filename,os.path.join(self.dir,self.tmp_dir))
                    if os.path.splitext(member.filename)[1] == ".xml":
                        members.append(os.path.join(self.dir,self.tmp_dir, member.filename))
                else:
                    self.helper.log_warning("    - skipping oversized member %s of size %d from zip file %s" % (member.filename, member.file_size, file))
            zf.close()
            # Prepare to move zipfile to donedir
            dest = os.path.join(self.dir,self.done_dir,os.path.basename(file))
            self.helper.log_info("    - moving %s to %s" % (file,dest))
            try:
                shutil.move(file,dest)
            except Exception, e:
                self.helper.log_error("    - error moving %s to done_dir with exception %s" % (file, e))
            return members


    def process_gzfile(self, file):
        """ Decompress a gz file, write to temp, move to done_dir, and return a list of the extracted member """
        members = []
        with open(file, 'rb') as f:
            self.helper.log_info("    - extracting gz file %s" % file)
            data = f.read()
            zobj = zlib.decompressobj(zlib.MAX_WBITS|32)
            try:
                # Protect against gzip bombs by limiting decompression to max_size
                unz  = zobj.decompress(data, self.max_size)
            except Exception,e:
                self.helper.log_info("    - moving bad gz file %s to bad_dir because of %s" % (file,e))
                dest = os.path.join(self.dir,self.bad_dir,os.path.basename(file))
                try:
                    shutil.move(file,dest)
                except Exception, e:
                    self.helper.log_error("    - error moving %s to bad_dir with exception %s" % (file, e))
            else:
                if zobj.unconsumed_tail:
                    del data
                    del zobj
                    del unz
                    self.helper.log_warning("   - decompression exceeded limit")
                else:
                    del data
                    member = os.path.join(self.dir,self.tmp_dir,os.path.basename(os.path.splitext(file)[0]))
                    with open(member,"w") as m:
                        self.helper.log_info("   - writing to %s" % member)
                        m.write(unz)
                        m.close
                        del unz
                        # Prepare to move gz file to done_dir
                        dest = os.path.join(self.dir,self.done_dir,os.path.basename(file))
                        self.helper.log_info("    - moving %s to %s" % (file,dest))
                        try:
                            shutil.move(file,dest)
                        except Exception, e:
                            self.helper.log_error("    - error moving %s to done_dir with exception %s" % (file, e))
                        m.close
                        members.append(member)
        return members

    def process_xmlfile_to_lines(self, file, keep):
        """ Processes an XML from from a given directory to Splunk events,
            move it to the done_dir,
            and return a list of lines in kv format
        """
        events = []
        with open(file, 'r') as f:
            self.helper.log_info("    - start parsing xml file %s with do_resolve=%s" % (file, self.do_resolve))
            try:
                # To protect against various XML threats we use the parse function from defusedxml.ElementTree
                xmldata = parse(f)
            except Exception, e:
                raise Exception("    - error in file %s with exception: %s" % (file,e))
            else:
                #for line in self.rua2kv(xmldata):
                #    events.append(line) 
                f.close
                lines = self.rua2kv(xmldata)
                del xmldata
                dest = os.path.join(self.dir,self.done_dir,os.path.basename(file))
                self.helper.log_info("    - moving %s to %s" % (file,dest))
                if keep:
                    try:
                        shutil.move(file,dest)
                    except Exception, e:
                        self.helper.log_error("    - error moving %s to done_dir with exception %s" % (file, e))
                else:
                    try:
                        self.helper.log_info("    - deleting %s" % file)
                        os.remove(file)
                    except Exception, e:
                        self.helper.log_error("    - error deleting file %s from tmp_dir with exception %s" % (file, e))
            return lines


    def check_dir(self):
        """ Check if dir is readable and writable
        """
        try:
            list = os.listdir(self.dir)
        except Exception as e:
            raise Exception("Error: directory %s not readable with exception %s" % (self.dir, e))
            return False
        else:
            if os.access(self.dir, os.W_OK):
                return True
            else:
                self.helper.log_error("Directory %s not writable" % self.dir)
                return False


    def make_dir(self,dir):
        """ Create a directory
        """
        try:
            os.makedirs(dir)
        except OSError as e:
            if e.errno != errno.EEXIST:
               raise Exception("Cannot create directory %s with exception %s" % (dir,e))


    def init_dirs(self):
        """ Create tmp_dir and done_dir if they don't exist
        """
        tmp_dir  = os.path.join(self.dir,self.tmp_dir)
        done_dir = os.path.join(self.dir,self.done_dir)
        bad_dir  = os.path.join(self.dir,self.bad_dir)
        if self.check_dir():
            self.make_dir(tmp_dir)
            self.make_dir(done_dir)
            self.make_dir(bad_dir)
            return True
        else:
            return False

        
    def write_event(self, lines):
        try:
            for line in lines:
                event = self.helper.new_event(line, time=None, host=None, index=self.helper.get_output_index(), source=self.helper.get_input_type(), sourcetype=self.helper.get_sourcetype(), done=True, unbroken=True)
                self.ew.write_event(event)
        except Exception, e:
            raise Exception("Exception in write_event(): %s" % e)

        
    def process_incoming(self):
        """ Processes the main incoming directory
        """
        events = []
        self.helper.log_info("Start processing incoming directory %s with %d quiet_secs" % (self.dir, self.quiet_secs))
        fileslist = self.filter_quiet_files(self.list_incoming())
        for file in fileslist:
            ext = os.path.splitext(file)[1]
            if ext == ".zip":
                self.helper.log_info("Start processing zip file %s" % file)
                for xmlfile in self.process_zipfile(file):
                    lines = self.process_xmlfile_to_lines(xmlfile,0)
                    self.write_event(lines)
            elif ext == ".gz":
                self.helper.log_info("Start processing gz file %s" % file)
                for xmlfile in self.process_gzfile(file):
                    lines = self.process_xmlfile_to_lines(xmlfile,0)
                    self.write_event(lines)
            elif ext == ".xml":
                self.helper.log_info("Start processing xml file %s" % file)
                lines = self.process_xmlfile_to_lines(file,1)
                self.write_event(lines)
            else:
                self.helper.log_info("Ignoring file %s" % file)
        self.helper.log_info("Ended processing incoming directory %s" % self.dir)

