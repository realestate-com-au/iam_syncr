from iam_syncr.errors import BadAmazon

from contextlib import contextmanager
import boto

class LeaveAlone(object):
    """Used to differentiate between None and not specified in a call signature"""

class AmazonMixin:
    @contextmanager
    def catch_boto_400(self, message, heading=None, document=None, **info):
        """Turn a BotoServerError 400 into a BadAmazon"""
        try:
            yield
        except boto.exception.BotoServerError as error:
            if error.status == 400:
                if heading or document:
                    print("=" * 80)
                    if heading:
                        print(heading)
                    print(document)
                    print("=" * 80)
                raise BadAmazon(message, error_code=error.code, error_message=error.message, **info)
            else:
                raise

    @contextmanager
    def ignore_boto_404(self):
        """Ignore a BotoServerError 404"""
        try:
            yield
        except boto.exception.BotoServerError as error:
            if error.status == 404:
                pass
            else:
                raise

    def print_change(self, symbol, typ, changes=None, document=None, **kwargs):
        """Print out a change"""
        values = ", ".join("{0}={1}".format(key, val) for key, val in sorted(kwargs.items()))
        print("{0} {1}({2})".format(symbol, typ, values))
        if changes:
            for change in changes:
                print("\n".join("\t{0}".format(line) for line in change.split('\n')))
        elif document:
            print("\n".join("\t{0}".format(line) for line in document.split('\n')))

    def change(self, symbol, typ, **kwargs):
        """Print out a change and then do the change if not doing a dry run"""
        self.print_change(symbol, typ, **kwargs)
        if not self.amazon.dry_run:
            try:
                yield
            except:
                raise
            else:
                self.amazon.changes = True

