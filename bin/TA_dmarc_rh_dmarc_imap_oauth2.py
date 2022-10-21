
import ta_dmarc_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'interval',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^\-[1-9]\d*$|^\d*$""", 
        )
    ), 
    field.RestField(
        'index',
        required=True,
        encrypted=False,
        default='default',
        validator=validator.String(
            min_len=1, 
            max_len=80, 
        )
    ), 
    field.RestField(
        'global_account',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'imap_server',
        required=True,
        encrypted=False,
        default='outlook.office365.com',
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'imap_username',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'oauth2_authority',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'oauth2_scope',
        required=True,
        encrypted=False,
        default='https://outlook.office365.com/.default',
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'resolve_ip',
        required=False,
        encrypted=False,
        default=True,
        validator=None
    ), 
    field.RestField(
        'validate_xml',
        required=False,
        encrypted=False,
        default=True,
        validator=None
    ), 
    field.RestField(
        'validate_dkim',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'imap_mailbox',
        required=True,
        encrypted=False,
        default='INBOX',
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'output_format',
        required=True,
        encrypted=False,
        default='json',
        validator=None
    ), 
    field.RestField(
        'batch_size',
        required=False,
        encrypted=False,
        default='100',
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 

    field.RestField(
        'disabled',
        required=False,
        validator=None
    )

]
model = RestModel(fields, name=None)



endpoint = DataInputModel(
    'dmarc_imap_oauth2',
    model,
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
