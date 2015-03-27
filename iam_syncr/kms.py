from iam_syncr.statements import Statements
from iam_syncr.amazon.kms import AmazonKms
from iam_syncr.helpers import listified
from iam_syncr.errors import BadPolicy

import logging

log = logging.getLogger("iam_syncr.kms")

class Kms(object):
    def __init__(self, name, definition, amazon, templates=None):
        self.name = name
        self.grant = []
        self.amazon = amazon
        self.definition = definition
        self.statements = Statements(name, "key", amazon.account_id, amazon.accounts, location=self.definition.get("location"))
        self.permission = list(self.statements.make_permission_statements({"principal": {"iam": "root"}, "action": "kms:*", "resource": "*", "Sid": ""}, allow=True))

    def setup(self):
        """Raise errors if the definition doesn't make sense"""
        self.location = self.definition.get("location")
        self.description = self.definition.get("description")

        self.connection = self.amazon.kms_connection_for(self.location)
        if not self.description:
            raise BadPolicy("Please define a description", key=self.name)

        if "admin_users" in self.definition:
            policy = {"principal": self.definition["admin_users"], "action": "kms:*", "resource": { "kms": "__self__" }, "Sid": ""}
            for statement in self.statements.make_permission_statements(policy, allow=True):
                self.permission.append(statement)

        for key, default_allow in (("permission", None), ("allow_permission", True), ("deny_permission", False)):
            for policy in listified(self.definition, key):
                for statement in self.statements.make_permission_statements(policy, allow=default_allow):
                    self.permission.append(statement)

        for policy in listified(self.definition, "grant"):
            if not isinstance(policy, dict):
                raise BadPolicy("Grant must be a dictionary of atleast {grantee, operations}", got=policy, key=self.name)

            if "grantee" not in policy and "operations" not in policy:
                raise BadPolicy("Grant must be a dictionary of atleast {grantee, operations}", got=list(policy.keys()), key=self.name)

            policy['grantee'] = list(self.statements.iam_arns_from_specification(policy['grantee']))
            if 'retiree' in policy:
                policy['retiree'] = list(self.statements.iam_arns_from_specification(policy['retiree']))

            for thing in ('grantee', 'retiree'):
                if thing in policy:
                    if len(policy[thing]) > 1:
                        raise BadPolicy("Can only have one {0}".format(thing), got=len(policy[thing]), key=self.name)
                    policy[thing] = policy[thing][0]

            self.grant.append(policy)

    def resolve(self):
        """Make sure this key exists and has only what policies we want it to have"""
        permission_document = self.make_permission_document(self.permission)

        amazon_keys = AmazonKms(self.amazon, self.connection)
        key_info = amazon_keys.key_info(self.name)
        if not key_info:
            amazon_keys.create_key(self.name, self.description, permission_document=permission_document)
        else:
            amazon_keys.modify_key(self.name, self.description, permission_document=permission_document)

        amazon_keys.modify_grant(self.name, self.description, grant=self.grant)

    def make_permission_document(self, permissions):
        """Return a document for these permissions, or None if no permissiosn"""
        if not permissions:
            return
        return self.statements.make_document(permissions)

