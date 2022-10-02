# encoding = utf-8

from dmarc.imap2dir import Imap2Dir
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
            
    opt_imap_server    = definition.parameters.get("imap_server", None)
    opt_use_ssl        = True
    opt_global_account = definition.parameters.get('global_account', None)
    opt_imap_username  = None
    opt_oauth2_authority = None
    opt_oauth2_scope   = None
    opt_imap_mailbox   = definition.parameters.get("imap_mailbox", None)
    opt_validate_dkim  = definition.parameters.get('validate_dkim', None)
    opt_batch_size     = int(definition.parameters.get('batch_size', None))

    try:
        tmp_dir = create_tmp_dir(helper)
        i2d = Imap2Dir(helper, 
                        opt_imap_server,
                        tmp_dir,
                        opt_use_ssl,
                        opt_global_account,
                        opt_imap_username,
                        opt_oauth2_authority,
                        opt_oauth2_scope,
                        opt_imap_mailbox,
                        opt_validate_dkim,
                        opt_batch_size)
        i2d.get_imap_connectivity()
    finally:
        remove_tmp_dir(helper, tmp_dir)

def collect_events(helper, ew):
    opt_imap_server    = helper.get_arg("imap_server")
    opt_use_ssl        = True
    opt_global_account = helper.get_arg('global_account')
    opt_imap_username  = None
    opt_oauth2_authority = None
    opt_oauth2_scope   = None
    opt_imap_mailbox   = helper.get_arg("imap_mailbox")
    opt_resolve_ip     = helper.get_arg('resolve_ip')
    opt_validate_xml   = helper.get_arg('validate_xml')
    opt_validate_dkim  = helper.get_arg('validate_dkim')
    opt_output_format  = helper.get_arg('output_format')
    opt_batch_size     = int(helper.get_arg('batch_size'))

    loglevel   = helper.get_log_level()
    helper.set_log_level(loglevel)

    tmp_dir = create_tmp_dir(helper)
    i2d = Imap2Dir(helper, 
                    opt_imap_server,
                    tmp_dir,
                    opt_use_ssl,
                    opt_global_account,
                    opt_imap_username,
                    opt_oauth2_authority,
                    opt_oauth2_scope,
                    opt_imap_mailbox,
                    opt_validate_dkim,
                    opt_batch_size)
    try:
        filelist = i2d.process_incoming()
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