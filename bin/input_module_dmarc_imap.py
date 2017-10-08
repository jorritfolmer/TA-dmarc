
# encoding = utf-8

import os
import sys
import time
import datetime
import ssl
from imapclient import IMAPClient

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    pass

def collect_events(helper, ew):
    """Implement your data collection logic here """

    opt_imap_server    = helper.get_arg("imap_server")
    opt_use_ssl        = helper.get_arg("use_ssl")
    opt_global_account = helper.get_arg('global_account')

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    with IMAPClient(opt_imap_server, use_uid=True,ssl=True, ssl_context=context) as server:
        server.login(opt_global_account["username"], opt_global_account["password"])
        select_info = server.select_folder('INBOX')
        response = server.fetch(messages, ['UID', 'BODY[HEADER.FIELDS (SUBJECT)'])
        for msgid, data in response.iteritems():
            helper.log_info('%s - %s %s' % (msgid, data['UID'], data['SUBJECT']))

