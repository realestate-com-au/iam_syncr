from iam_syncr.amazon.documents import AmazonDocuments
from iam_syncr.amazon.common import AmazonMixin
from iam_syncr.errors import BadAlias, BadRole

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

    def modify_grant(self, alias, description, grant):
        """Modify grants on a key"""
        key = self.key_info(alias)
        if not key:
            raise BadAlias("Where did the key go?", alias=alias)

        key_id = key["KeyId"]
        new_grants = []
        current_grants = self.connection.list_grants(key_id)["Grants"]
        for policy in current_grants:
            policy["Operations"] = sorted(policy["Operations"])

        for policy in grant:
            nxt = {"GranteePrincipal": self.user_from_arn(policy["grantee"]), "RetireePrincipal": self.user_from_arn(policy.get("Retiree")), "Operations": sorted(policy["operations"]), "Constraints": policy.get("constraints"), "GrantTokens": policy.get("grant_tokens")}
            nxt = dict((key, val) for key, val in nxt.items() if val is not None)

            if not any(all(current[key] == val for key, val in nxt.items()) for current in current_grants):
                new_grants.append(policy)

        for policy in new_grants:
            for _ in self.change("+", "key_grant", key=alias, grantee=policy["grantee"]):
                self.connection.create_grant(key_id, policy["grantee"], retiring_principal=policy.get("retiree"), operations=policy["operations"], constraints=policy.get("constraints"), grant_tokens=policy.get("grant_tokens"))

    def user_from_arn(self, arn):
        """Convert an arn into the user id"""
        if arn is None:
            return

        role_ids = [item["role_id"] for item in self.amazon.all_roles if item['arn'] == arn]
        if len(role_ids) != 1:
            raise BadRole("Didn't find a single role id for specified arn", got=role_ids, arn=arn)

        return role_ids[0]

