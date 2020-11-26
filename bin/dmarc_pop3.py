import ta_dmarc_declare

import os
import sys
import time
import datetime
import json

import modinput_wrapper.base_modinput
from solnlib.packages.splunklib import modularinput as smi



import input_module_dmarc_pop3 as input_module

bin_dir = os.path.basename(__file__)

'''
    Do not edit this file!!!
    This file is generated by Add-on builder automatically.
    Add your modular input logic to file input_module_dmarc_pop3.py
'''
class ModInputdmarc_pop3(modinput_wrapper.base_modinput.BaseModInput):

    def __init__(self):
        if 'use_single_instance_mode' in dir(input_module):
            use_single_instance = input_module.use_single_instance_mode()
        else:
            use_single_instance = False
        super(ModInputdmarc_pop3, self).__init__("ta_dmarc", "dmarc_pop3", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputdmarc_pop3, self).get_scheme()
        scheme.title = ("DMARC pop3")
        scheme.description = ("Go to the add-on\'s configuration UI and configure modular inputs under the Inputs menu.")
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True

        scheme.add_argument(smi.Argument("name", title="Name",
                                         description="",
                                         required_on_create=True))

        """
        For customized inputs, hard code the arguments here to hide argument detail from users.
        For other input types, arguments should be get from input_module. Defining new input types could be easier.
        """
        scheme.add_argument(smi.Argument("global_account", title="Global Account",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("pop3_server", title="POP3 server",
                                         description="Connect to the specified POP3 server with TLS (port 995)",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("resolve_ip", title="Resolve IP",
                                         description="Resolve the source_ip field in the DMARC aggregate reports.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("validate_xml", title="Validate XML",
                                         description="Validate the aggregate reports against the DMARC XSD. Results are included in the field vendor_rua_xsd_validation.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("validate_dkim", title="Validate DKIM",
                                         description="(Beta) Validate the DKIM signatures in the mail headers. Results are currently only available in DEBUG log.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("output_format", title="Output format",
                                         description="",
                                         required_on_create=False,
                                         required_on_edit=False))
        return scheme

    def get_app_name(self):
        return "TA-dmarc"

    def validate_input(self, definition):
        """validate the input stanza"""
        input_module.validate_input(self, definition)

    def collect_events(self, ew):
        """write out the events"""
        input_module.collect_events(self, ew)

    def get_account_fields(self):
        account_fields = []
        account_fields.append("global_account")
        return account_fields

    def get_checkbox_fields(self):
        checkbox_fields = []
        checkbox_fields.append("resolve_ip")
        checkbox_fields.append("validate_xml")
        checkbox_fields.append("validate_dkim")
        return checkbox_fields

    def get_global_checkbox_fields(self):
        if self.global_checkbox_fields is None:
            checkbox_name_file = os.path.join(bin_dir, 'global_checkbox_param.json')
            try:
                if os.path.isfile(checkbox_name_file):
                    with open(checkbox_name_file, 'r') as fp:
                        self.global_checkbox_fields = json.load(fp)
                else:
                    self.global_checkbox_fields = []
            except Exception as e:
                self.log_error('Get exception when loading global checkbox parameter names. ' + str(e))
                self.global_checkbox_fields = []
        return self.global_checkbox_fields

if __name__ == "__main__":
    exitcode = ModInputdmarc_pop3().run(sys.argv)
    sys.exit(exitcode)
