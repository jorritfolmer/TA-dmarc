from builtins import str
import tempfile
import shutil


# Copyright 2017 Jorrit Folmer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


def create_tmp_dir(helper):
    try:
        tmpdir = tempfile.mkdtemp()
    except Exception as e:
        raise Exception(
            "Exception creating temporary directory %s: %s" %
            (tmpdir, str(e)))
    else:
        helper.log_debug("Success creating temporary directory %s" % (tmpdir))
        return tmpdir


def remove_tmp_dir(helper, tmpdir):
    if tmpdir is not None:
        try:
            shutil.rmtree(tmpdir)
        except Exception as e:
            raise Exception(
                "Exception deleting temporary directory %s: %s" %
                (tmpdir, str(e)))
        else:
            helper.log_debug(
                "Success deleting temporary directory %s" %
                (tmpdir))
            return True
    return False
