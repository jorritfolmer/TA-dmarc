# Changelog

## 2.6.1

- Improved exception handling of character sets handling

## 2.6.0

- Added support for other character sets than utf-8, iso-8859-1

## 2.5.1

- Fixed issues that prevented addition of new directory inputs

## 2.5.0

- Only process actual DMARC aggregate reports and ignore other XML files
- Changed validation result field to include multiple XSD validations

## 2.4.1

- Fixed issues that prevented addition of new inputs after clean install of TA-dmarc

## 2.4.0

- Added ability to deviate from the default IMAP mailbox "INBOX"
- Added XSD validation results in a new field
- Introduced a relaxed XSD to cover DMARC draft, DMARC rfc and caught-in-the-wild usage
  (Thanks to Steven Hilton for the Pull Request)

## 2.3.0

- Added JSON output to better preserve report structure, issue #4. 
  (Thanks to Steven Hilton for the Pull Request)
- Added unit tests for rua2json() and rua2kv() 
  (Thanks to Steven Hilton for the Pull Request)
- Fixed missing metadata and record information in key=value output, issue #5. 
  (Thanks to Steven Hilton for reporting these issues)
- Fixed incorrect action field from the authentication datamodel to use policy_evaluated instead of auth_results. The policy is leading in message authentication.
- Moved to user field instead of incorrect src_user field from the authentication datmodel. Keeping src_user field for backward compatibility.

## 2.2.0

- Added non-standard mimetypes used by Verizon and Yahoo to the dmarc reports attachment filter, issue #3
  (Thanks to John for reporting this issue)

## 2.1.1

- Fixed reading reports with absolute paths from zip files, issue #2
  (Thanks to Steve Myers for reporting this issue)

## 2.1.0

- Added DMARC XML validation against DMARC XSD:
  New checkbox added to the input configure screens.
  Appends a new event field: vendor_rua_xsd_validation = (success|failure|unknown)
- Removed forgotten use_ssl input parameter from inputs.conf.spec

## 2.0.0

Improved checkpointing:

- Store individual records in KVstore instead of using a single serialized Python set.
- Corrected misconfigured key in KVstore collection

Addressed concerns from Splunk Cert Admin:

- enforced use of TLS for IMAP input, by removing TLS checkbox
- ensure tmp directories are always cleaned up, by using try finally for both directory and imap inputs
- ensure the add-on won't write outside of splunk designated directories by implementing KVstore checkpointing for DMARC directory inputs instead of using file ops to bad/, done/ or tmp/ dirs.

NOTES BEFORE UPGRADING FROM v1.x TO 2.0.0:
Because of the changes to KVstore logic, the add-on will re-index every report on IMAP, leading to duplicate events.

## 1.2.1

- Corrected issues from Splunk Cert Admin

## 1.2.0

- Added support for aggregate reports in non-multipart mail messages

## 1.1.0

- Added IMAP support and message uid checkpointing

## 1.0.0

- Initial release with directory based messages ingestion
