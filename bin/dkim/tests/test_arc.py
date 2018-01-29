# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>
#
# This has been modified from the original software.
# Copyright (c) 2016 Google, Inc.
# Contact: Brandon Long <blong@google.com>

import os.path
import unittest
import time

import dkim


def read_test_data(filename):
    """Get the content of the given test data file.
    """
    path = os.path.join(os.path.dirname(__file__), 'data', filename)
    with open(path, 'rb') as f:
        return f.read()


class TestSignAndVerify(unittest.TestCase):
    """End-to-end signature and verification tests."""

    def setUp(self):
        self.message = read_test_data("test.message")
        self.key = read_test_data("test.private")

    def dnsfunc(self, domain):
        sample_dns = """\
k=rsa; \
p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANmBe10IgY+u7h3enWTukkqtUD5PR52T\
b/mPfjC0QJTocVBq6Za/PlzfV+Py92VaCak19F4WrbVTK5Gg5tW220MCAwEAAQ=="""

        _dns_responses = {
          'example._domainkey.canonical.com.': sample_dns,
          'test._domainkey.example.com.': read_test_data("test.txt"),
          # dnsfunc returns empty if no txt record
          'missing._domainkey.example.com.': '',
          '20120113._domainkey.gmail.com.': """k=rsa; \
p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Kd87/UeJjenpabgbFwh\
+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQ\
s8g3FgD2Ap3ZB5DekAo5wMmk4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbb\
hzY8i+RQ9DpSVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5Oct\
MEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZK9vlfuac0598H\
Y+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21MycBX5jYchHjPY/wIDAQAB"""
        }
        try:
            domain = domain.decode('ascii')
        except UnicodeDecodeError:
            return None
        self.assertTrue(domain in _dns_responses,domain)
        return _dns_responses[domain]

    def test_verifies(self):
        # A message verifies after being signed.
        sig_lines = dkim.arc_sign(
            self.message, b"test", b"example.com", self.key,
            b"test.domain: none", dkim.CV_None)
        (cv, res, reason) = dkim.arc_verify(b''.join(sig_lines) + self.message, dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Pass)

    """def test_multiple_instances_verify(self):
        # A message verifies after being signed multiple times.
        message = self.message
        sig_lines = dkim.arc_sign(
            message, b"test", b"example.com", self.key,
            "test.domain: none", dkim.CV_None)
        message = ''.join(sig_lines) + message
        (cv, res, reason) = dkim.arc_verify(message, dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Pass)

        for x in range(10):
          sig_lines = dkim.arc_sign(
              message, b"test", b"example.com", self.key,
              "test.domain: arc=pass", dkim.CV_Pass)
          message = ''.join(sig_lines) + message
          (cv, res, reason) = dkim.arc_verify(message, dnsfunc=self.dnsfunc)
          self.assertEquals(cv, dkim.CV_Pass)

    def test_multiple_instances_verify_fail(self):
        # A message return CV_Fail if signed as failure.
        message = self.message
        sig_lines = dkim.arc_sign(
            message, b"test", b"example.com", self.key,
            "test.domain: none", dkim.CV_None)
        message = ''.join(sig_lines) + message
        (cv, res, reason) = dkim.arc_verify(message, dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Pass)

        sig_lines = dkim.arc_sign(
            message, b"test", b"example.com", self.key,
            "test.domain: arc=pass", dkim.CV_Fail)
        message = ''.join(sig_lines) + message
        # A conforming signer wouldn't sign as pass after a fail.
        sig_lines = dkim.arc_sign(
            message, b"test", b"example.com", self.key,
            "test.domain: arc=pass", dkim.CV_Pass)
        message = ''.join(sig_lines) + message

        (cv, res, reason) = dkim.arc_verify(message, dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Fail)

    def test_altered_body_fails(self):
        # An altered body fails verification.
        sig_lines = dkim.arc_sign(
            self.message, b"test", b"example.com", self.key,
            "test.domain: none", dkim.CV_None)
        (cv, res, reason) = dkim.arc_verify(''.join(sig_lines) + self.message + b"foo", dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Fail)

    def test_dns_pk_mismatch_fails(self):
        # DNS public key doesn't match signing private key.
        sig_lines = dkim.arc_sign(
            self.message, b"example", b"canonical.com", self.key,
            "test.domain: none", dkim.CV_None)
        (cv, res, reason) = dkim.arc_verify(''.join(sig_lines) + self.message, dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Fail)

    def test_dns_missing_fails(self):
        # DNS public key missing fails verify
        sig_lines = dkim.arc_sign(
            self.message, b"missing", b"example.com", self.key,
            "test.domain: none", dkim.CV_None)
        (cv, res, reason) = dkim.arc_verify(''.join(sig_lines) + self.message, dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Fail)"""

def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
