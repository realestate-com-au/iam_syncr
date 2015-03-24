from iam_syncr.amazon.documents import AmazonDocuments
from iam_syncr.amazon.common import AmazonMixin
from iam_syncr.errors import BadPolicy

import logging
import boto

log = logging.getLogger("iam_syncr.amazon.buckets")

class AmazonBuckets(AmazonMixin, object):
    def __init__(self, amazon):
        self.amazon = amazon
        self.documents = AmazonDocuments()
        self.connection = amazon.s3_connection

    def bucket_info(self, name):
        """Return what amazon knows about this bucket"""
        try:
            return self.connection.get_bucket(name)
        except boto.exception.S3ResponseError as error:
            if error.status == 404:
                return False
            raise

    def current_policy(self, bucket):
        """Return the current policy for this bucket"""
        try:
            return bucket.get_policy()
        except boto.exception.S3ResponseError as error:
            if error.status == 404:
                return "{}"
            raise

    def has_bucket(self, name):
        """Return whether amazon has info about this role"""
        return bool(self.bucket_info(name))

    def create_bucket(self, name, location, permission_document=None):
        """Create a role"""
        with self.catch_boto_400("Couldn't create bucket", name=name):
            for _ in self.change("+", "bucket[{0}] ".format(location), name=name):
                self.connection.create_bucket(name, location=location)

        # And add our permissions
        if permission_document:
            with self.catch_boto_400("Couldn't add policy", "Bucket {0} - Permission document".format(name), permission_document, bucket=name):
                for _ in self.change("+", "bucket_policy", bucket=name, document=permission_document):
                    self.bucket_info(name).set_policy(permission_document)

    def modify_bucket(self, name, location, permission_document):
        """Modify a bucket"""
        log.info("Inspecting bucket\tname=%s", name)
        bucket = self.bucket_info(name)
        if not bucket:
            return

        current_location = bucket.get_location()
        if current_location != location:
            raise BadPolicy("The location of the bucket is wrong. You need to delete and recreate the bucket to have it in your specified location", current=current_location, wanted=location)

        current_policy = self.current_policy(bucket)
        changes = list(self.documents.compare_two_documents(current_policy, permission_document))
        if changes:
            with self.catch_boto_400("Couldn't modify policy", "Bucket {0} policy".format(name), permission_document, bucket=name):
                for _ in self.change("M", "bucket_policy", bucket=name, changes=changes):
                    bucket.set_policy(permission_document)

