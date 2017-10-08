
# encoding = utf-8

import os
import sys
import time
import datetime
import tempfile
import shutil
from dmarc.imap2dir import Imap2Dir
from dmarc.dir2splunk import Dir2Splunk


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
    opt_resolve_ip     = helper.get_arg('resolve_ip')
    
    loglevel   = helper.get_log_level()
    helper.set_log_level(loglevel)

    i2d = Imap2Dir(helper, opt_imap_server, opt_use_ssl, opt_global_account)
    filelist = i2d.process_incoming()
    if len(filelist)>0:
        d2s = Dir2Splunk(ew, helper, i2d.tmpdir, 0, opt_resolve_ip)
        if d2s.init_dirs():
            d2s.process_incoming()
            i2d.remove_tmp_dir()
