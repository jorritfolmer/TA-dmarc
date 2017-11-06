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


class Imap2Dir:
    """ This class:
        - gets DMARC XML aggregate report attachments from a mailbox
        - and saves them to a provided tmp directory
    """


    def __init__(self, helper, opt_imap_server, tmp_dir, opt_use_ssl, opt_global_account):
        # Instance variables:
        self.helper             = helper
        self.opt_imap_server    = opt_imap_server
        self.opt_use_ssl        = opt_use_ssl
        self.opt_global_account = opt_global_account
        self.tmp_dir            = tmp_dir
        self.server             = None


    def get_imap_connectivity(self):
        """ Connect to imap server and close the connection """
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        messages = []
        try:
            if self.opt_use_ssl:
                self.server=IMAPClient(self.opt_imap_server, use_uid=True, ssl=True, ssl_context=context)
            else:
                self.server=IMAPClient(self.opt_imap_server, use_uid=True, ssl=False)
        except Exception, e:
            raise Exception("Error connecting to %s with exception %s" % (self.opt_imap_server, str(e)))
        else:
            self.helper.log_debug('get_imap_connectivity: successfully connected to %s' % self.opt_imap_server)
 

    def get_dmarc_messages(self):
        """ Connect to imap server and return a list of msg uids that match the subject 'Report domain:' """
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        messages = []
        try:
            if self.opt_use_ssl:
                self.server=IMAPClient(self.opt_imap_server, use_uid=True, ssl=True, ssl_context=context)
            else:
                self.server=IMAPClient(self.opt_imap_server, use_uid=True, ssl=False)
        except Exception, e:
            raise Exception("Error connecting to %s with exception %s" % (self.opt_imap_server, str(e)))
        else:
            self.helper.log_debug('get_dmarc_messages: successfully connected to %s' % self.opt_imap_server)
            self.server.login(self.opt_global_account["username"], self.opt_global_account["password"])
            select_info = self.server.select_folder('INBOX')
            messages = self.server.search('SUBJECT "Report domain:"')
            self.helper.log_debug('get_dmarc_messages: %d messages match subject "Report domain:"' % len(messages))
        return messages


    def get_dmarc_message_bodies(self, messages):
            """ Return the full message bodies from the list of message uids """
            response = self.server.fetch(messages, ['RFC822'])
            return response


    def write_part_to_file(self, uid, part):
        """ Write the selected message part to file """
        filename = part.get_filename()
        filename = os.path.join(self.tmp_dir, os.path.basename(filename))
        try:
             open(filename, 'wb').write(part.get_payload(decode=True))
        except Exception, e:
             raise Exception("Error writing to filename %s with exception %s" % (filename, str(e)))
        else:
             self.helper.log_debug('write_part_to_file: saved file %s from uid %d' % (filename, uid))
             return filename


    def save_reports_from_message_bodies(self, response):
        """ Find zip and gzip attachments in the response, and write them to disk 
            Return a list of filenames that were written
        """
        filelist = []
        for uid, data in response.items():
            msg = email.message_from_string(data['RFC822'])
            if msg.is_multipart():
                self.helper.log_debug('save_reports_from_message_bodies: start multipart processing of msg uid  %d' % uid)
                for part in msg.get_payload():
                    ctype = part.get_content_type()
                    if ctype == "application/zip":
                        filename = self.write_part_to_file(uid, part)
                        filelist.append(filename)
                    elif ctype == "application/gzip":
                        filename = self.write_part_to_file(uid, part)
                        filelist.append(filename)
                    elif ctype == "application/x-gzip":
                        filename = self.write_part_to_file(uid, part)
                        filelist.append(filename)
                    elif ctype == "application/xml":
                        filename = self.write_part_to_file(uid, part)
                        filelist.append(filename)
                    elif ctype == "text/xml":
                        filename = self.write_part_to_file(uid, part)
                        filelist.append(filename)
                    else:
                        self.helper.log_debug('save_reports_from_message_bodies: skipping content-type %s of msg uid %d' % (ctype, uid))
            else:
                self.helper.log_debug('save_reports_from_message_bodies: start non-multipart processing of msg uid  %d' % uid)
                ctype = msg.get_content_type()
                if ctype == "application/zip":
                    filename = self.write_part_to_file(uid, msg)
                    filelist.append(filename)
                elif ctype == "application/gzip":
                    filename = self.write_part_to_file(uid, msg)
                    filelist.append(filename)
                elif ctype == "application/x-gzip":
                    filename = self.write_part_to_file(uid, msg)
                    filelist.append(filename)
                elif ctype == "application/xml":
                    filename = self.write_part_to_file(uid, msg)
                    filelist.append(filename)
                elif ctype == "text/xml":
                    filename = self.write_part_to_file(uid, msg)
                    filelist.append(filename)
                else:
                    self.helper.log_debug('save_reports_from_message_bodies: skipping content-type %s of msg uid %d' % (ctype, uid))
            # mark msg as seen in KVstore
            self.save_check_point(uid, msg)
        return filelist

    def save_check_point(self, uid, msg):
        key = "%s_%s_%d" % (self.opt_imap_server, self.opt_global_account["username"], uid)
        date = email.utils.mktime_tz(email.utils.parsedate_tz(msg.get('Date')))
        value = "input=dmarc_imap, server=%s, username=%s, uid=%d, timestamp_utc=%d, subject='%s'" % (self.opt_imap_server, self.opt_global_account["username"], uid, date, msg.get('Subject'))
        try:
            self.helper.save_check_point(key, value)
        except Exception, e:
            raise Exception("Error saving checkpoint data with with exception %s" % str(e))


    def filter_seen_messages(self, messages):
        """ From a given list of uids, return only the ones we haven't seen before 
            based on the presence of a KVstore key.
            This key takes into account: imap server, imap account and imap msg uid
        """
        seen_uids = set()
        for uid in messages:
            key = "%s_%s_%d" % (self.opt_imap_server, self.opt_global_account["username"], uid)
            if(self.helper.get_check_point(key) != None):
                seen_uids.add(uid)
        new_uids = set(messages) - seen_uids
        self.helper.log_debug('filter_seen_messages: uids on imap   %s' % set(messages))
        self.helper.log_debug('filter_seen_messages: uids on imap   %s' % set(messages))
        self.helper.log_debug('filter_seen_messages: uids in checkp %s' % seen_uids)
        self.helper.log_debug('filter_seen_messages: uids new       %s' % new_uids)
        return new_uids
 
    def process_incoming(self):
        """ Main function """
        filelist=[]
        self.helper.log_info("Start processing imap server %s with use_ssl %s" % (self.opt_imap_server, self.opt_use_ssl))
        messages = self.get_dmarc_messages()
        new_messages = self.filter_seen_messages(messages)
        if len(new_messages) > 0:
            self.helper.log_info('Start processing %d new messages of %d on %s' % ( len(new_messages), len(messages), self.opt_imap_server))
            response = self.get_dmarc_message_bodies(new_messages)
            filelist = self.save_reports_from_message_bodies(response)
            self.helper.log_info('Ended processing %d new messages with %d attachments' % ( len(new_messages), len(filelist)))
        self.helper.log_info("Ended processing imap server %s" % self.opt_imap_server)
        return filelist


