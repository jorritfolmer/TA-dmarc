from builtins import str
from builtins import range
from builtins import object
import os
import ssl
import email
import dkim
import dns
import poplib


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


class Pop2Dir(object):
    """ This class:
        - gets DMARC XML aggregate report attachments from a mailbox
        - and saves them to a provided tmp directory
    """

    def __init__(
            self,
            helper,
            opt_pop3_server,
            tmp_dir,
            opt_use_ssl,
            opt_global_account,
            opt_validate_dkim):
        # Instance variables:
        self.helper = helper
        self.opt_pop3_server = opt_pop3_server
        self.opt_use_ssl = opt_use_ssl
        self.opt_global_account = opt_global_account
        self.opt_validate_dkim = opt_validate_dkim
        self.tmp_dir = tmp_dir
        self.server = None

    def get_pop3_connectivity(self):
        """ Connect to pop3 server and close the connection """
        try:
            if self.opt_use_ssl:
                self.server = poplib.POP3_SSL(self.opt_pop3_server)
            else:
                self.server = poplib.POP3(self.opt_pop3_server)
        except Exception as e:
            raise Exception(
                "Error connecting to %s with exception %s" %
                (self.opt_pop3_server, str(e)))
        else:
            self.helper.log_debug(
                'get_pop3_connectivity: successfully connected to %s' %
                self.opt_pop3_server)

    def byte2str(self, obj):
        """ Convert byte string onto Unicode string using UTF-8 encoding
            Works with byte strings and byte string lists """
        encoding = "utf-8"
        if isinstance(obj, list):
            if len(obj)>0 and not isinstance(obj[0], str):
                self.helper.log_debug(
                    "conversion from list of %s onto list of <class 'str'>" %
                    type(obj[0]))
                return [ s.decode(encoding) for s in obj ]
            elif not isinstance(obj, str):
                self.helper.log_debug(
                    "conversion from %s onto <class 'str'>" %
                    type(obj))
                return obj.decode(encoding)
            return obj

    def get_dmarc_messages(self):
        """ Connect to pop3 server and return a list of ALL msg uids
            Unlike the IMAP equivalent filtering based on Subject is done elsewhere """
        messages = []
        try:
            if self.opt_use_ssl:
                self.server = poplib.POP3_SSL(self.opt_pop3_server)
                self.server.user(self.opt_global_account["username"])
                self.server.pass_(self.opt_global_account["password"])
            else:
                self.server = poplib.POP3(self.opt_pop3_server)
                self.server.user(self.opt_global_account["username"])
                self.server.pass_(self.opt_global_account["password"])
        except Exception as e:
            raise Exception(
                "Error connecting to %s with exception %s" %
                (self.opt_pop3_server, str(e)))
        else:
            self.helper.log_debug(
                'get_dmarc_messages: successfully connected to %s' %
                self.opt_pop3_server)
            messages = self.byte2str(self.server.uidl()[1])
            self.helper.log_info(
                'get_dmarc_messages: %d messages' %
                len(messages))
        return messages

    def get_dmarc_message_bodies(self, messages):
        """ Return the full message bodies from the list of message uids
            but only if the subject matches Report domain """
        response = {}
        for uid in messages:
            self.helper.log_debug('get_dmarc_message_bodies: got uid "%s", using uid "%s"' % (uid, uid.split()[0]))
            msg = "\n".join(self.byte2str(self.server.retr(uid.split()[0])[1]))
            msgobj = email.message_from_string(msg)
            if "report domain:" in msgobj.get("Subject").lower():
                self.helper.log_debug(
                    'get_dmarc_message_bodies: found dmarc message: uid %s with subject %s' %
                    (uid, msgobj.get("Subject")))
                response[uid] = {}
                response[uid][b'RFC822'] = msg
        return response

    def write_part_to_file(self, uid, part):
        """ Write the selected message part to file """
        filename = part.get_filename()
        filename = os.path.join(self.tmp_dir, os.path.basename(filename))
        try:
            open(filename, 'wb').write(part.get_payload(decode=True))
        except Exception as e:
            raise Exception(
                "Error writing to filename %s with exception %s" %
                (filename, str(e)))
        else:
            self.helper.log_debug(
                'write_part_to_file: saved file %s from uid %s' %
                (filename, uid))
            return filename

    def dkim_verify(self, msg, uid):
        """ Verify DKIM signature(s) from a given RFC822 message
            Currently only generated debug logging """
        try:
            obj = dkim.DKIM(msg)
        except Exception as e:
            self.helper.log_info(
                'dkim_verify: exception verifying msg uid %s with %s' %
                (uid, str(e)))
        else:
            sigheaders = [
                (x, y) for x, y in obj.headers if x.lower() == b"dkim-signature"]
            self.helper.log_debug(
                'dkim_verify: msg uid %s has %d DKIM signatures' %
                (uid, len(sigheaders)))
            for i in range(0, len(sigheaders)):
                try:
                    res = obj.verify(i)
                except Exception as e:
                    self.helper.log_info(
                        'dkim_verify: exception verifying msg uid %s with %s' %
                        (uid, str(e)))
                else:
                    if res:
                        self.helper.log_debug(
                            'dkim_verify: msg uid %s signature %d ok from domain %s selector %s' %
                            (uid, i, obj.domain, obj.selector))
                    else:
                        self.helper.log_debug(
                            'dkim_verify: msg uid %s signature %d fail from domain %s selector %s' %
                            (uid, i, obj.domain, obj.selector))

    def save_reports_from_message_bodies(self, response):
        """ Find xml, zip and gzip attachments in the response, and write them to disk
            Return a list of filenames that were written
        """
        filelist = []
        for uid, data in list(response.items()):
            if self.opt_validate_dkim:
                self.dkim_verify(data.get(b'RFC822',''), uid)
            msg = email.message_from_string(data.get(b'RFC822',''))
            if msg.is_multipart():
                self.helper.log_debug(
                    'save_reports_from_message_bodies: start multipart processing of msg uid  %s' %
                    uid)
                for part in msg.get_payload():
                    ctype = part.get_content_type()
                    if self.check_eligible_mimetype(ctype, uid):
                        filename = self.write_part_to_file(uid, part)
                        filelist.append(filename)
            else:
                self.helper.log_debug(
                    'save_reports_from_message_bodies: start non-multipart processing of msg uid  %s' %
                    uid)
                ctype = msg.get_content_type()
                if self.check_eligible_mimetype(ctype, uid):
                    filename = self.write_part_to_file(uid, msg)
                    filelist.append(filename)
                else:
                    self.helper.log_debug(
                        'save_reports_from_message_bodies: skipping content-type %s of msg uid %s' %
                        (ctype, uid))
            # mark msg as seen in KVstore
            self.save_check_point(uid.split()[1], msg)
        return filelist

    def check_eligible_mimetype(self, ctype, uid):
        """ Check if a given mimetype is eligible for further processing
            Returns true of false
        """
        self.helper.log_debug(
            'check_eligible_mimtype: checking content-type %s of msg uid %s' %
            (ctype, uid))
        if ctype == "application/zip":
            return True
        elif ctype == "application/gzip":
            return True
        elif ctype == "application/x-gzip":
            return True
        elif ctype == "application/octet-stream":
            # Non-standard mimetype used by Amazon SES dmarc reports
            return True
        elif ctype == "application-x-gzip":
            # Non-standard mimetype used by Comcast dmarc reports
            return True
        elif ctype == "application/x-zip-compressed":
            # Non-standard mimetype used by Yahoo dmarc reports
            return True
        elif ctype == "application/xml":
            return True
        elif ctype == "text/xml":
            return True
        else:
            self.helper.log_debug(
                'check_eligible_mimtype: skipping content-type %s of msg uid %s' %
                (ctype, uid))
            return False

    def save_check_point(self, uid, msg):
        """ Save checkpointing info for a given uid and msg struct """
        key = "%s_%s_%s" % (self.opt_pop3_server,
                            self.opt_global_account["username"], uid)
        date = email.utils.mktime_tz(email.utils.parsedate_tz(msg.get('Date')))
        value = "input=dmarc_pop, server=%s, username=%s, uid=%s, timestamp_utc=%d, subject='%s'" % (
            self.opt_pop3_server, self.opt_global_account["username"], uid, date, msg.get('Subject'))
        try:
            self.helper.save_check_point(key, value)
        except Exception as e:
            raise Exception(
                "Error saving checkpoint data with with exception %s" %
                str(e))

    def filter_seen_messages(self, messages):
        """ From a given list of uids, return only the ones we haven't seen before
            based on the presence of a KVstore key.
            This key takes into account: pop server, pop account and pop msg uid
        """
        seen_uids = set()
        for uid in messages:
            key = "%s_%s_%s" % (self.opt_pop3_server,
                                self.opt_global_account["username"], uid.split()[1])
            if self.helper.get_check_point(key) is not None:
                seen_uids.add(uid)
        new_uids = set(messages) - seen_uids
        self.helper.log_debug(
            'filter_seen_messages: uids on pop3   %s' %
            set(messages))
        self.helper.log_debug(
            'filter_seen_messages: uids in checkp %s' %
            seen_uids)
        self.helper.log_debug(
            'filter_seen_messages: uids new       %s' %
            new_uids)
        return new_uids

    def process_incoming(self):
        """ Main function """
        filelist = []
        self.helper.log_info(
            "Start processing pop3 server %s with use_ssl %s" %
            (self.opt_pop3_server, self.opt_use_ssl))
        messages = self.get_dmarc_messages()
        new_messages = self.filter_seen_messages(messages)
        if len(new_messages) > 0:
            self.helper.log_info(
                'Start processing %d new messages of %d on %s' %
                (len(new_messages), len(messages), self.opt_pop3_server))
            response = self.get_dmarc_message_bodies(new_messages)
            filelist = self.save_reports_from_message_bodies(response)
            self.helper.log_info(
                'Ended processing %d new messages with %d attachments' %
                (len(new_messages), len(filelist)))
        self.helper.log_info(
            "Ended processing pop3 server %s" %
            self.opt_pop3_server)
        return filelist
