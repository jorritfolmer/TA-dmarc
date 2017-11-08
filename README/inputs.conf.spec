[dmarc_imap://<name>]
global_account = Use the account configured in the setup tab
imap_server = Connect to the specified IMAP server with TLS (port 993)
resolve_ip = Resolve the source_ip field in the DMARC aggregate reports.
validate_xml = Validate the aggregate reports against the DMARC XSD. Results are included in the field vendor_rua_xsd_validation.

[dmarc_directory://<name>]
dmarc_directory = Location where DMARC aggregate report files are dropped
quiet_time = Ignore files that have a modification time of less than n seconds ago.
resolve_ip = Resolve the source_ip field in the DMARC XML aggregate report
validate_xml = Validate the aggregate report XML against the DMARC XSD. Results are included in the field vendor_rua_xsd_validation.