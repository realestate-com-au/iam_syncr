from iam_syncr.amazon.buckets import AmazonBuckets
from iam_syncr.statements import Statements
from iam_syncr.helpers import listified
from iam_syncr.errors import SyncrError

import logging
import six

log = logging.getLogger("iam_syncr.buckets")

class Bucket(object):
    def __init__(self, name, definition, amazon, templates=None):
        self.name = name
        self.definition = definition
        self.statements = Statements(name, "bucket", amazon.account_id, amazon.accounts)

        self.amazon = amazon
        self.amazon_buckets = AmazonBuckets(amazon)

        self.permission = []

    def setup(self):
        """Raise errors if the definition doesn't make sense"""
        self.tags = self.definition.get("tags", {})
        if type(self.tags) != dict or any(not isinstance(tag_name, six.string_types) or not isinstance(tag_val, six.string_types) for tag_name, tag_val in self.tags.items()):
            raise SyncrError("Bucket tags should be a dictionary of {<string> : <string>}", got=self.tags)

        self.location = self.definition.get("location", "ap-southeast-2")
        for key, default_allow in (("permission", None), ("allow_permission", True), ("deny_permission", False)):
            for policy in listified(self.definition, key):
                for statement in self.statements.make_permission_statements(policy, allow=default_allow):
                    self.permission.append(statement)

    def resolve(self):
        """Make sure this user exists and has only what policies we want it to have"""
        permission_document = self.make_permission_document(self.permission)

        bucket_info = self.amazon_buckets.bucket_info(self.name)
        if not bucket_info:
            self.amazon_buckets.create_bucket(self.name, self.location, permission_document=permission_document, tags=self.tags)
        else:
            self.amazon_buckets.modify_bucket(self.name, self.location, permission_document=permission_document, tags=self.tags)

    def make_permission_document(self, permissions):
        """Return a document for these permissions, or None if no permissiosn"""
        if not permissions:
            return
        return self.statements.make_document(permissions)

