# Changelog

## 2.2.0

- Added non-standard mimetypes used by Verizon and Yahoo to the dmarc reports attachment filter
  (Thanks to John for reporting this issue)

## 2.1.1

- Fixed reading reports with absolute paths from zip files
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
