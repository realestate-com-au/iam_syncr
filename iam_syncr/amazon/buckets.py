from iam_syncr.amazon.documents import AmazonDocuments
from iam_syncr.amazon.common import AmazonMixin
from iam_syncr.errors import BadPolicy

from boto.s3.tagging import TagSet, Tags
from itertools import chain
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
            return bucket.get_policy().decode('utf-8')
        except boto.exception.S3ResponseError as error:
            if error.status == 404:
                return "{}"
            raise

    def current_tags(self, bucket):
        """Return the tags associated with this bucket"""
        try:
            return dict(chain.from_iterable([(tag.key, tag.value) for tag in tags] for tags in bucket.get_tags()))
        except boto.exception.S3ResponseError as error:
            if error.status == 404:
                return {}
            raise

    def has_bucket(self, name):
        """Return whether amazon has info about this role"""
        return bool(self.bucket_info(name))

    def create_bucket(self, name, location, permission_document=None, tags=None):
        """Create a role"""
        with self.catch_boto_400("Couldn't create bucket", name=name):
            for _ in self.change("+", "bucket[{0}] ".format(location), name=name):
                self.connection.create_bucket(name, location=location)

        # And add our permissions
        if permission_document:
            with self.catch_boto_400("Couldn't add policy", "Bucket {0} - Permission document".format(name), permission_document, bucket=name):
                for _ in self.change("+", "bucket_policy", bucket=name, document=permission_document):
                    self.bucket_info(name).set_policy(permission_document)

    def modify_bucket(self, name, location, permission_document, tags):
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

        self.modify_bucket_tags(name, bucket, tags)

    def modify_bucket_tags(self, name, bucket, tags):
        """Modify the tags on a bucket"""
        changes = {}
        new_tags = TagSet()
        current_tags = self.current_tags(bucket)

        for tag_name, tag_val in tags.items():
            if tag_name in current_tags:
                if current_tags[tag_name] != tag_val:
                    changes[tag_name] = ("modify", tag_name, current_tags[tag_name], tag_val)
            elif tag_name not in current_tags:
                changes[tag_name] = ("create", tag_name, None, tag_val)

            new_tags.add_tag(tag_name, tag_val)

        for tag_name in current_tags:
            if tag_name not in tags:
                changes[tag_name] = ("delete", tag_name, current_tags[tag_name], None)

        if changes:
            if not new_tags:
                for _ in self.change("D", "bucket_tags", bucket=name, changes=["Delete all tags"]):
                    bucket.delete_tags()
            else:
                one_letter = "M" if any(typ in ("modify", "delete") for typ, _, _, _ in changes.values()) else "C"
                for _ in self.change(one_letter, "bucket_tag", bucket=name, changes=["{0} {1} from {2} to {3}".format(*change) for change in changes.values()]):
                    t = Tags()
                    t.add_tag_set(new_tags)
                    bucket.set_tags(t)

