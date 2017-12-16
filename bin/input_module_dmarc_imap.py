# encoding = utf-8

from dmarc.imap2dir import Imap2Dir
from dmarc.dir2splunk import Dir2Splunk
from dmarc.helper import create_tmp_dir
from dmarc.helper import remove_tmp_dir


# IMPORTANT
# Edit only the validate_input and collect_events functions.
# Do not edit any other part in this file.
# This file is generated only once when creating the modular input.

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""

    opt_imap_server    = definition.parameters.get("imap_server", None)
    opt_use_ssl        = True
    opt_global_account = definition.parameters.get('global_account', None)

    try:
        tmp_dir = create_tmp_dir(helper)
        i2d = Imap2Dir(helper, opt_imap_server, tmp_dir, opt_use_ssl, opt_global_account)
        i2d.get_imap_connectivity()
    finally:
        remove_tmp_dir(helper, tmp_dir)

def collect_events(helper, ew):
    """Implement your data collection logic here """

    opt_imap_server    = helper.get_arg("imap_server")
    opt_use_ssl        = True
    opt_global_account = helper.get_arg('global_account')
    opt_resolve_ip     = helper.get_arg('resolve_ip')
    opt_validate_xml   = helper.get_arg('validate_xml')
    opt_output_format  = "kv"

    loglevel   = helper.get_log_level()
    helper.set_log_level(loglevel)

    tmp_dir = create_tmp_dir(helper)
    i2d = Imap2Dir(helper, opt_imap_server, tmp_dir, opt_use_ssl, opt_global_account)
    try:
        filelist = i2d.process_incoming()
        if len(filelist)>0:
            d2s = Dir2Splunk(ew, helper, tmp_dir, 0, opt_resolve_ip, opt_validate_xml, opt_output_format, False)
            if d2s.check_dir():
                d2s.process_incoming()
    finally:
        remove_tmp_dir(helper, tmp_dir)
