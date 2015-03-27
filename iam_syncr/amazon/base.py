from iam_syncr.errors import SyncrError

from boto.iam.connection import IAMConnection
from boto.s3.connection import S3Connection
from boto.kms.layer1 import KMSConnection
import logging
import boto
import sys

log = logging.getLogger("iam_syncr.amazon.base")

class Amazon(object):
    dry_run = False
    connection = None

    # Account info that is overridden by __init__
    accounts = None
    account_id = None
    account_name = None

    @classmethod
    def set_boto_useragent(self, app_name, version):
        """Put this app in the useragent used by boto"""
        __import__("boto")
        useragent = sys.modules["boto.connection"].UserAgent
        if app_name not in useragent:
            sys.modules["boto.connection"].UserAgent = "{0} {1}/{2}".format(useragent, app_name, version)

    def __init__(self, account_id, account_name, accounts, dry_run=False):
        self.changes = False
        self.dry_run = dry_run
        self.accounts = accounts
        self.account_id = account_id
        self.account_name = account_name

    def setup(self):
        """Make sure our current credentials are for this account and set self.connection"""
        try:
            connection = IAMConnection()
        except boto.exception.NoAuthHandlerFound:
            raise SyncrError("Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY before running this script (your aws credentials)")

        try:
            result = connection.list_roles()
        except boto.exception.BotoServerError as error:
            if error.status == 403:
                raise SyncrError("Your credentials aren't allowed to look at iam :(")
            else:
                raise

        roles = self.all_roles = result["list_roles_response"]["list_roles_result"]["roles"]
        if not roles:
            raise SyncrError("There are no roles in your account, I can't figure out the account id")

        amazon_account_id = roles[0]['arn'].split(":")[4]
        if str(self.account_id) != str(amazon_account_id):
            raise SyncrError("Please use credentials for the right account", expect=self.account_id, got=amazon_account_id)

        # If reached this far, the credentials belong to the correct account :)
        self.connection = connection
        return connection

    @property
    def s3_connection(self):
        if getattr(self, "_s3_connection", None) is None:
            try:
                self._s3_connection = S3Connection()
            except boto.exception.NoAuthHandlerFound:
                raise SyncrError("Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY before running this script (your aws credentials)")
        return self._s3_connection

    def kms_connection_for(self, location):
        if getattr(self, "_kms_connections", None) is None:
            self._kms_connections = {}

        if location not in self._kms_connections:
            try:
                self._kms_connections[location] = boto.kms.connect_to_region(location)
            except boto.exception.NoAuthHandlerFound:
                raise SyncrError("Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY before running this script (your aws credentials)")
        return self._kms_connections[location]

