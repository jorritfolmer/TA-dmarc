# encoding = utf-8

from dmarc.pop2dir import Pop2Dir
from dmarc.dir2splunk import Dir2Splunk
from dmarc.helper import create_tmp_dir
from dmarc.helper import remove_tmp_dir

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    opt_pop3_server    = definition.parameters.get("pop3_server", None)
    opt_use_ssl        = True
    opt_global_account = definition.parameters.get('global_account', None)
    opt_validate_dkim  = definition.parameters.get('validate_dkim', None)

    try:
        tmp_dir = create_tmp_dir(helper)
        p2d = Pop2Dir(helper, opt_pop3_server, tmp_dir, opt_use_ssl, opt_global_account, opt_validate_dkim)
        p2d.get_pop3_connectivity()
    finally:
        remove_tmp_dir(helper, tmp_dir)

def collect_events(helper, ew):
    opt_pop3_server    = helper.get_arg("pop3_server")
    opt_use_ssl        = True
    opt_global_account = helper.get_arg('global_account')
    opt_resolve_ip     = helper.get_arg('resolve_ip')
    opt_validate_xml   = helper.get_arg('validate_xml')
    opt_validate_dkim  = helper.get_arg('validate_dkim')
    opt_output_format  = helper.get_arg('output_format')

    loglevel   = helper.get_log_level()
    helper.set_log_level(loglevel)

    tmp_dir = create_tmp_dir(helper)
    p2d = Pop2Dir(helper, opt_pop3_server, tmp_dir, opt_use_ssl, opt_global_account, opt_validate_dkim)
    try:
        filelist = p2d.process_incoming()
        if len(filelist)>0:
            d2s = Dir2Splunk(ew, helper, tmp_dir, 0, opt_resolve_ip, opt_validate_xml, opt_output_format, False)
            if d2s.check_dir():
                d2s.process_incoming()
    finally:
        remove_tmp_dir(helper, tmp_dir)

# PSEUDOCODE for refactor:
#
# mailbox = DMARCMailbox(imap, ssl, account)
# for uid, message in mailbox.get_dmarc_messages()
#     mail = DMARCMail(message)
#     dkimvrfy = mail.dkim_verify()
#     for file in mail.get_dmarc_attachments()
#         rua = DMARCfile(file)
#         res_xmlvalidation = rua.get_xml_validation()
#         res_feedback = rua.get_rua_feedback()
#         event = DMARCEvent(res_feedback, res_xmlvalidation, dkimvrfy)
#         event.save_event()
#     mailbox.save_checkpoint(uid)