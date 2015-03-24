from iam_syncr.amazon.documents import AmazonDocuments
from iam_syncr.amazon.common import AmazonMixin

import boto.kms.exceptions
import logging
import boto

log = logging.getLogger("iam_syncr.amazon.kms")

class AmazonKms(AmazonMixin, object):
    def __init__(self, amazon, connection):
        self.amazon = amazon
        self.documents = AmazonDocuments()
        self.connection = connection

    def key_info(self, alias):
        """Return what amazon knows about this key"""
        try:
            return self.connection.describe_key("alias/{0}".format(alias))["KeyMetadata"]
        except boto.kms.exceptions.NotFoundException:
            return False

    def current_policy(self, key):
        """Return the current policy for this key"""
        try:
            return self.connection.get_key_policy(key["KeyId"], "default")["Policy"]
        except boto.kms.exceptions.NotFoundException:
            return "{}"

    def has_key(self, alias):
        """Return whether amazon has info about this key"""
        return bool(self.key_info(alias))

    def create_key(self, alias, description, permission_document=None):
        """Create a key"""
        with self.catch_boto_400("Couldn't create key", document=permission_document, alias=alias):
            for _ in self.change("+", "key", alias=alias):
                key = self.connection.create_key(permission_document, description)["KeyMetadata"]
                self.connection.create_alias("alias/{0}".format(alias), key["KeyId"])

    def modify_key(self, alias, description, permission_document):
        """Modify a key"""
        key = self.key_info(alias)
        if not key:
            return

        current_description = key["Description"]
        if current_description != description:
            for _ in self.change("M", "key_description", key=alias, description=description):
                self.connection.update_key_description(key["KeyId"], description)

        current_policy = self.current_policy(key)
        changes = list(self.documents.compare_two_documents(current_policy, permission_document))
        if changes:
            with self.catch_boto_400("Couldn't modify policy", "Key {0} policy".format(alias), permission_document, key=alias):
                for _ in self.change("M", "key_policy", key=alias, changes=changes, description=description):
                    self.connection.put_key_policy(key["KeyId"], 'default', permission_document)

