import os
import sys
import time
import datetime
import socket
import errno
import ssl
from imapclient import IMAPClient
import email
import tempfile
import pickle
import shutil

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


class Imap2Dir:
    """ This class:
        - gets DMARC aggregate report attachments from a mailbox
        - and saves them to a temp directory

        Any further processing  be done with the Dir2Splunk class,
    """


    def __init__(self, helper, opt_imap_server, opt_use_ssl, opt_global_account):
        # Instance variables:
        self.helper             = helper
        self.opt_imap_server    = opt_imap_server
        self.opt_use_ssl        = opt_use_ssl
        self.opt_global_account = opt_global_account
        self.tmpdir             = None
        self.server             = None
        if self.helper.get_check_point("seen_uids") != None:
            self.seen_uids = pickle.loads(self.helper.get_check_point("seen_uids"))
        else:
            self.seen_uids = set()


    def add_seen_uid(self, uid):
        self.seen_uids.add(uid)


    def get_dmarc_messages(self):
        """ Connect to imap server and return a list of msg uids that match the subject 'Report domain:' """
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        messages = []
        try:
            if self.opt_use_ssl:
                self.server=IMAPClient(self.opt_imap_server, use_uid=True,ssl=True, ssl_context=context)
            else:
                self.server=IMAPClient(self.opt_imap_server, use_uid=True,ssl=False)
        except Exception, e:
            raise Exception("Error connecting to %s with exception %s" % (self.opt_imap_server, str(e)))
        else:
            self.helper.log_info('Successfully connected to %s' % self.opt_imap_server)
            self.server.login(self.opt_global_account["username"], self.opt_global_account["password"])
            select_info = self.server.select_folder('INBOX')
            messages = self.server.search('SUBJECT "Report domain:"')
            self.helper.log_info('%d messages match subject "Report domain:"' % len(messages))
        return messages


    def get_dmarc_message_bodies(self, messages):
            """ Return the full message bodies from the list of message uids """
            response = self.server.fetch(messages, ['RFC822'])
            return response


    def write_part_to_file(self, part):
        """ Write the selected message part to file """
        filename = part.get_filename()
        filename = os.path.join(self.tmpdir, os.path.basename(filename))
        try:
             open(filename, 'wb').write(part.get_payload(decode=True))
        except Exception, e:
             raise Exception("Error writing to filename %s with exception %s" % (filename, str(e)))
        else:
             self.helper.log_debug('    - saved %s' % filename)
             return filename


    def create_tmp_dir(self):
        try:
            self.tmpdir = tempfile.mkdtemp()
        except Exception, e:
            raise Exception("Exception creating temporary directory %s: %s" % (self.tmpdir, str(e)))
        else:
            self.helper.log_debug("Success creating temporary directory %s" % (self.tmpdir))
            return True;


    def remove_tmp_dir(self):
        if self.tmpdir != None:
            try:
                shutil.rmtree(self.tmpdir)
            except Exception, e:
                raise Exception("Exception deleting temporary directory %s: %s" % (self.tmpdir, str(e)))
            else:
                self.helper.log_debug("Success deleting temporary directory %s" % (self.tmpdir))
                return True
        return False


    def save_reports_from_message_bodies(self, response):
        """ Find zip and gzip attachments in the response, and write them to disk """
        filelist = []
        if self.create_tmp_dir():
            for uid, data in response.items():
                msg = email.message_from_string(data['RFC822'])
                for part in msg.get_payload():
                    ctype = part.get_content_type()
                    if ctype == "application/zip":
                        filename = self.write_part_to_file(part)
                        self.add_seen_uid(uid)
                        filelist.append(filename)
                    elif ctype == "application/gzip":
                        filename = self.write_part_to_file(part)
                        self.add_seen_uid(uid)
                        filelist.append(filename)
                    else:
                        self.helper.log_debug('    - skipping content-type %s of msg uid %d' % (ctype, uid))
            self.helper.save_check_point("seen_uids", pickle.dumps(self.seen_uids))
        return filelist


    def filter_seen_messages(self, messages):
        """ From a given list of uids, return only the ones we haven't seen before """
        new_uids = set(messages) - self.seen_uids
        self.helper.log_debug('filter_seen_messages: uids on imap   %s' % set(messages))
        self.helper.log_debug('filter_seen_messages: uids in checkp %s' % self.seen_uids)
        self.helper.log_debug('filter_seen_messages: uids new       %s' % new_uids)
        return new_uids
 
    def process_incoming(self):
            """ Main function """
            filelist=[]
            messages = self.get_dmarc_messages()
            new_messages = self.filter_seen_messages(messages)
            if len(new_messages) > 0:
                response = self.get_dmarc_message_bodies(new_messages)
                filelist = self.save_reports_from_message_bodies(response)
            return filelist


