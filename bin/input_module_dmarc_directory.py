
# encoding = utf-8

import os
import sys
import time
import datetime
from Dmarc import Dmarc

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""

    opt_dmarc_directory = definition.parameters.get('dmarc_directory', None)
    opt_quiet_time = definition.parameters.get('quiet_time', None)
    opt_resolve_ip = definition.parameters.get('resolve_ip', None)

    # Even something pedestrian like this fail validation in the input config gui:
    # "Validation for scheme=dmarc_directory failed: The script returned with exit status 1."


    try:
        test = int(opt_quiet_time)   
    except Exception as e:
        raise ValueError("Error: quiet_time not an integer")

    dmarc = Dmarc(None, helper, opt_dmarc_directory, opt_quiet_time, opt_resolve_ip)
    if not dmarc.check_dir():
        raise ValueError("Error: something wrong with the directory")

def collect_events(helper, ew):
    """Implement your data collection logic here"""

    opt_dmarc_directory = helper.get_arg('dmarc_directory')
    opt_quiet_time = int(helper.get_arg('quiet_time'))
    opt_resolve_ip = helper.get_arg('resolve_ip')

    loglevel   = helper.get_log_level()
    helper.set_log_level(loglevel)

    dmarc = Dmarc(ew, helper, opt_dmarc_directory, opt_quiet_time, opt_resolve_ip)
    if dmarc.init_dirs():
        dmarc.process_incoming()

