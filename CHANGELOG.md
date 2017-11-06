# Changelog

## 2.0.0

Improved checkpointing:

- Store individual records in KVstore instead of using a single serialized Python set.
- Corrected misconfigured key in KVstore collection

Addressed concerns from Splunk Cert Admin:

- enforced use of TLS for IMAP input, by removing TLS checkbox
- ensure tmp directories are always cleaned up, by using try finally for both directory and imap inputs
- ensure the add-on won't write outside of splunk designated directories by implementing KVstore checkpointing for DMARC directory inputs instead of using file ops to bad/, done/ or tmp/ dirs.


## 1.2.1

- Corrected issues from Splunk Cert Admin

## 1.2.0

- Added support for aggregate reports in non-multipart mail messages

## 1.1.0

- Added IMAP support and message uid checkpointing

## 1.0.0

- Initial release with directory based messages ingestion
