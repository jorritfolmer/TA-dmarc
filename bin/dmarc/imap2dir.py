from builtins import str
from builtins import range
from builtins import object
import os
import ssl
import email
from imapclient import IMAPClient
import dkim
import dns
import msal

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


class Imap2Dir(object):
    """ This class:
        - gets DMARC XML aggregate report attachments from a mailbox
        - and saves them to a provided tmp directory
    """

    def __init__(
            self,
            helper,
            opt_imap_server,
            tmp_dir,
            opt_use_ssl,
            opt_global_account,
            opt_imap_username,
            opt_oauth2_authority,
            opt_oauth2_scope,
            opt_imap_mailbox,
            opt_validate_dkim,
            opt_batch_size):
            
        # Instance variables:
        self.helper = helper
        self.opt_imap_server = opt_imap_server
        self.tmp_dir = tmp_dir
        self.opt_use_ssl = opt_use_ssl
        self.opt_global_account = opt_global_account
        self.opt_imap_username = opt_imap_username    
        self.opt_oauth2_authority = opt_oauth2_authority
        self.opt_oauth2_scope = opt_oauth2_scope
        self.opt_imap_mailbox = 'INBOX' if opt_imap_mailbox is None else opt_imap_mailbox
        self.opt_validate_dkim = opt_validate_dkim
        self.opt_batch_size = 100 if opt_batch_size is None else opt_batch_size
        self.server = None

    def get_imap_connectivity(self):
        """ Connect to imap server and close the connection """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.verify_mode = ssl.CERT_NONE
        try:
            if self.opt_use_ssl:
                self.server = IMAPClient(
                    self.opt_imap_server,
                    use_uid=True,
                    ssl=True,
                    ssl_context=context)
            else:
                self.server = IMAPClient(
                    self.opt_imap_server, use_uid=True, ssl=False)
        except Exception as e:
            raise Exception(
                "Error connecting to %s with exception %s" %
                (self.opt_imap_server, str(e)))
        else:
            self.helper.log_debug(
                'get_imap_connectivity: successfully connected to %s' %
                self.opt_imap_server)

    def get_dmarc_messages(self):
        """ Connect to imap server and return a list of msg uids that match the subject 'Report domain:' """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.verify_mode = ssl.CERT_NONE
        messages = []
        try:
            if self.opt_use_ssl:
                self.server = IMAPClient(
                    self.opt_imap_server,
                    use_uid=True,
                    ssl=True,
                    ssl_context=context)
            else:
                self.server = IMAPClient(
                    self.opt_imap_server, use_uid=True, ssl=False)
        except Exception as e:
            raise Exception(
                "Error connecting to %s with exception %s" %
                (self.opt_imap_server, str(e)))
        else:
            self.helper.log_debug(
                'get_dmarc_messages: successfully connected to %s' %
                self.opt_imap_server)

            ### 
            # OAauth2 vs BASIC login            
            if(self.opt_oauth2_authority is None):            
                self.server.login(
                    self.opt_global_account["username"],
                    self.opt_global_account["password"])
 
            else:
                app = msal.ConfidentialClientApplication(
                        client_id = self.opt_global_account["username"],
                        client_credential = self.opt_global_account["password"],
                        authority = self.opt_oauth2_authority
                    )

                self.helper.log_debug(
                        'get_dmarc_messages: acquiring token for client %s to access scope %s' %
                        (self.opt_global_account["username"],self.opt_oauth2_scope))               

                result = app.acquire_token_for_client(self.opt_oauth2_scope)
                        
                if "access_token" in result:
                    self.server.oauth2_login(
                        self.opt_imap_username,
                        result['access_token'])
                    self.helper.log_debug(
                        'get_dmarc_messages: successful login to %s using acquired token' %
                        (self.opt_imap_username))
                else:
                    self.helper.log_error(
                        'get_dmarc_messages: No access token found for client ID: %s  -  result %s' %
                        (self.opt_global_account["username"],result))
                    
            ###
            
            self.helper.log_debug(
                'get_dmarc_messages: will open folder %s in %s' %
                (self.opt_imap_mailbox,self.opt_imap_username))

            info = self.server.select_folder(self.opt_imap_mailbox)
            self.helper.log_info(
                'get_dmarc_messages: %s messages in folder %s' % (info.get(b'EXISTS', -1) , self.opt_imap_mailbox))
            messages = self.server.search('SUBJECT "Report domain:"')
            self.helper.log_info(
                'get_dmarc_messages: %d messages in folder %s match subject "Report domain:"' %
                (len(messages), self.opt_imap_mailbox))
        return messages

    def get_dmarc_message_bodies(self, messages):
        """ Return the full message bodies from the list of message uids """
        fetch_size = self.opt_batch_size
        response = dict()
        messageslist = list(messages)
        for x in range(0, len(messageslist), fetch_size):
            self.helper.log_info('get_dmarc_message_bodies: getting messages %s to %s' % (            
                str(x), str(min(x + fetch_size, len(messageslist)))))
            response.update(self.server.fetch(
                set(messageslist[x:x + fetch_size]), [b'RFC822']))
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
                'write_part_to_file: saved file %s from uid %d' %
                (filename, uid))
            return filename

    def dkim_verify(self, msg, uid):
        """ Verify DKIM signature(s) from a given RFC822 message
            Returns a result dict """
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
            msg = email.message_from_string(data.get(b'RFC822','').decode("utf-8", "replace"))
            if msg.is_multipart():
                self.helper.log_debug(
                    'save_reports_from_message_bodies: start multipart processing of msg uid  %d' %
                    uid)
                for part in msg.get_payload():
                    ctype = part.get_content_type()
                    if self.check_eligible_mimetype(ctype, uid):
                        filename = self.write_part_to_file(uid, part)
                        filelist.append(filename)
            else:
                self.helper.log_debug(
                    'save_reports_from_message_bodies: start non-multipart processing of msg uid  %d' %
                    uid)
                ctype = msg.get_content_type()
                if self.check_eligible_mimetype(ctype, uid):
                    filename = self.write_part_to_file(uid, msg)
                    filelist.append(filename)
                else:
                    self.helper.log_debug(
                        'save_reports_from_message_bodies: skipping content-type %s of msg uid %d' %
                        (ctype, uid))
            # mark msg as seen in KVstore
            self.save_check_point(uid, msg)
        return filelist

    def check_eligible_mimetype(self, ctype, uid):
        """ Check if a given mimetype is eligible for further processing
            Returns true of false
        """
        self.helper.log_debug(
            'check_eligible_mimtype: checking content-type %s of msg uid %d' %
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
                'check_eligible_mimtype: skipping content-type %s of msg uid %d' %
                (ctype, uid))
            return False

    def save_check_point(self, uid, msg):
        """ Save checkpointing info for a given uid and msg struct """
        key = "%s_%s_%d" % (self.opt_imap_server,
                            self.opt_global_account["username"], uid)
        date = email.utils.mktime_tz(email.utils.parsedate_tz(msg.get('Date')))
        value = "input=dmarc_imap, server=%s, username=%s, uid=%d, timestamp_utc=%d, subject='%s'" % (
            self.opt_imap_server, self.opt_global_account["username"], uid, date, msg.get('Subject'))
        try:
            self.helper.save_check_point(key, value)
        except Exception as e:
            raise Exception(
                "Error saving checkpoint data with with exception %s" %
                str(e))

    def filter_seen_messages(self, messages):
        """ From a given list of uids, return only the ones we haven't seen before
            based on the presence of a KVstore key.
            This key takes into account: imap server, imap account and imap msg uid
        """
        seen_uids = set()
        for uid in messages:
            key = "%s_%s_%d" % (self.opt_imap_server,
                                self.opt_global_account["username"], uid)
            if self.helper.get_check_point(key) is not None:
                seen_uids.add(uid)
        new_uids = set(messages) - seen_uids
        self.helper.log_debug(
            'filter_seen_messages: uids on imap   %s' %
            set(messages))
        self.helper.log_debug(
            'filter_seen_messages: uids on imap   %s' %
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
            "Start processing imap server %s with use_ssl %s" %
            (self.opt_imap_server, self.opt_use_ssl))
        messages = self.get_dmarc_messages()
        new_messages = self.filter_seen_messages(messages)
        if len(new_messages) > 0:
            self.helper.log_info(
                'Start processing %d new messages of %d on %s' %
                (len(new_messages), len(messages), self.opt_imap_server))
            response = self.get_dmarc_message_bodies(new_messages)
            filelist = self.save_reports_from_message_bodies(response)
            self.helper.log_info(
                'Ended processing %d new messages with %d attachments' %
                (len(new_messages), len(filelist)))
        self.helper.log_info(
            "Ended processing imap server %s" %
            self.opt_imap_server)
        return filelist
