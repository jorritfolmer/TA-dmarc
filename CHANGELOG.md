# Changelog

## 4.1.0

- Added OAuth2 support for Microsoft Office365 IMAP. (Thanks to hkelley for contributing code for this feature!)
- Fixed an exception when encountering illegal characters in xml attachment filenames. (Thanks to hkelley for reporting this issue)

## 4.0.0

- Recreated from scratch using Splunk Add-on Builder v4.1.1 to address various Splunk Cloud requirements

## 3.2.5

- Fixed str decode exception (Thanks to George Luong for reporing the issue)
- Fixed Py2/3 issues in POP3 input (Thanks to Constantin Oshmyan for reporting and fixing the issue)
- Fixed POP3 uidl persistence issue (Thanks to Constantin Oshmyan for reporting and fixing the issue)
- Fixed exception when encountering non-RFC822 items on DavMail (thanks to Diogo Silva for reporting the issue)

## 3.2.4

- Fixed exception in directory input. (Thanks to Georgi Georgiev for providing a patch)

## 3.2.3

- Added support for Splunk 8.1. (Thanks to Aaron Myers for reporting the issue)
- Fixed Gmail POP3 issue 

## 3.2.2

- Fixed exception when using add-on together with listenOnIPv6=yes
  (Thanks to gryphius for reporting this issue)

## 3.2.1

- Fixed resolving of IP addresses in src field.
  (Thanks to Martin Wright for reporting this issue)

## 3.2.0

- Added support for Splunk 8.x and Python 3.x

## 3.1.0

- Added field to make batch size configurable for IMAP inputs

## 3.0.2

- Lowercase keys and values in policy_published and records
  (Thanks to Christopher G Andrews for reporting this issue)

## 3.0.1

- Fixed connection reset errors for large IMAP mailboxes
  (Thanks to Mike Kolk for the patch)

## 3.0.0

- Added POP3 support
- Added initial DKIM signature checking
- Added support for zip files containing files like "aol com 12345 12355 xml"
- Moved JSON and KV output into a pulldown instead of seperate inputs
- Fixed timeout exceptions with some DKIM verifications

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
