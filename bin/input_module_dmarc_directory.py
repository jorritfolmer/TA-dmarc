# encoding = utf-8

from dmarc.dir2splunk import Dir2Splunk


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
    opt_dmarc_directory = definition.parameters.get('dmarc_directory', None)
    opt_quiet_time      = definition.parameters.get('quiet_time', None)
    opt_resolve_ip      = definition.parameters.get('resolve_ip', None)
    opt_validate_xml    = definition.parameters.get('validate_xml', None)
    opt_output_format   = definition.parameters.get('output_format', 'json')

    try:
        int(opt_quiet_time)   
    except Exception:
        raise ValueError("Error: quiet_time not an integer")

    d2s = Dir2Splunk(None, helper, opt_dmarc_directory, opt_quiet_time, opt_resolve_ip, opt_validate_xml, opt_output_format, False)
    d2s.check_dir()

def collect_events(helper, ew):
    opt_dmarc_directory = helper.get_arg('dmarc_directory')
    opt_quiet_time      = int(helper.get_arg('quiet_time'))
    opt_resolve_ip      = helper.get_arg('resolve_ip')
    opt_validate_xml    = helper.get_arg('validate_xml')
    opt_output_format   = helper.get_arg('output_format')

    loglevel   = helper.get_log_level()
    helper.set_log_level(loglevel)

    d2s = Dir2Splunk(ew, helper, opt_dmarc_directory, opt_quiet_time, opt_resolve_ip, opt_validate_xml, opt_output_format, True)
    if d2s.check_dir():
        d2s.process_incoming()

