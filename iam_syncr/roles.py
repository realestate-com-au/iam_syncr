from iam_syncr.errors import InvalidDocument, BadRole, BadPolicy
from iam_syncr.helpers import listify, listified, as_list

import logging
import json

log = logging.getLogger("iam_syncr.roles")

class RoleRemoval(object):
    def __init__(self, name, amazon):
        self.name = name
        self.amazon = amazon

    def setup(self):
        """Make sure our name is a string"""
        if not isinstance(self.name, basestring):
            raise BadRole("Told to remove a role, but not specified as a string", name=self.name, found_type=type(self.name))

    def resolve(self):
        """Remove the role"""
        self.amazon.remove_role(self.name)

class Role(object):
    def __init__(self, name, definition, amazon):
        self.name = name
        self.amazon = amazon
        self.definition = definition
        self.policy_name = "syncr_policy_{0}".format(self.name.replace("/", "__"))

        self.trust = {}
        self.distrust = {}
        self.permission = []

    def setup(self):
        """Raise errors if the definition doesn't make sense"""
        self.description = self.definition.get("description", "No description provided!")
        for key, store in (("allow_to_assume_me", self.trust), ("disallow_to_assume_me", self.distrust)):
            for principal in listified(self.definition, key):
                for namespace, principal in self.make_trust_principal(principal).items():
                    if namespace not in store:
                        store[namespace] = set()

                    if not isinstance(principal, list):
                        principal = [principal]

                    for specified in principal:
                        store[namespace].add(specified)

            for namespace, vals in store.items():
                store[namespace] = sorted(list(vals))

        for key, default_allow in (("permission", None), ("allow_permission", True), ("deny_permission", False)):
            for policy in listified(self.definition, key):
                for statement in self.make_permission_statements(policy, allow=default_allow):
                    self.permission.append(statement)

    def resolve(self):
        """Make sure this user exists and has only what policies we want it to have"""
        # Get the permission and trust document
        # Make sure they're both valid before continuing
        trust_document = self.make_trust_document(self.trust, self.distrust)
        permission_document = self.make_permission_document(self.permission)

        role_info = self.amazon.role_info(self.name)
        if not role_info:
            self.amazon.create_role(self.name, trust_document, policies={self.policy_name: permission_document})
        else:
            self.amazon.modify_role(role_info, self.name, trust_document, policies={self.policy_name: permission_document})

        if self.definition.get("make_instance_profile"):
            self.amazon.make_instance_profile(self.name)

    def make_trust_principal(self, principal):
        """Make a trust statement"""
        result = dict((key, val) for key, val in principal.items() if key[0].isupper())

        for specified in listified(principal, "service"):
            if specified == "ec2":
                specified = "ec2.amazonaws.com"
            listify(result, "Service").append(specified)

        for specified in listified(principal, "federated"):
            listify(result, "Federated").append(specified)

        if "iam" in principal:
            listify(result, "AWS").extend(self.iam_arns_from_specification(principal))

        return result

    def make_permission_statements(self, policy, allow=None):
        """
        Make zero or more permissions statements from a policy definition

        If allow is None and no allow or Effect is specified, an error is raised
        Otherwise we assume the truthiness of allow
        """
        result = dict((key, val) for key, val in policy.items() if key[0].isupper())

        if allow is None and "Effect" not in policy:
            if not isinstance(policy.get("allow"), bool):
                raise BadPolicy("Need to specify whether we allow this policy or not", policy=policy, role=self.name)
            result["Effect"] = ["Deny", "Allow"][policy["allow"]]
        elif allow is not None:
            result["Effect"] = ["Deny", "Allow"][allow]

        for key, dest in (("action", "Action"), ("notaction", "NotAction")):
            for specified in listified(policy, key):
                listify(result, dest).append(specified)

        for key, dest in (("resource", "Resource"), ("notresource", "NotResource")):
            for specified in listified(policy, key):
                listify(result, dest).extend(self.fill_out_resources(specified))

        if "Resource" not in result and "NotResource" not in result:
            raise BadPolicy("No Resource or NotResource was defined for policy", role=self.name, policy=policy)

        if "Action" not in result and "NotAction" not in result:
            raise BadPolicy("No Action or NotAction defined for this policy", role=self.name, policy=policy)

        yield result

    def fill_out_resources(self, resources):
        """Fill out the resources"""
        for resource in as_list(resources):
            if isinstance(resource, basestring):
                yield resource
            elif isinstance(resource, dict):
                for resource in self.expand_resource(resource):
                    yield resource
            else:
                raise BadPolicy("Resource should be a string or a dictionary", resource=resource)

    def expand_resource(self, resource):
        """Return a resource string for given resource"""
        if "iam" in resource:
            for found in self.iam_arns_from_specification(resource):
                yield found

        elif "s3" in resource:
            for bucket_key in listify(resource, "s3"):
                yield "arn:aws:s3:::{0}".format(bucket_key)
                if '/' not in bucket_key:
                    yield "arn:aws:s3:::{0}/*".format(bucket_key)

        else:
            raise BadPolicy("Unknown resource type", resource=resource)

    def iam_arns_from_specification(self, specification):
        """Get us an iam arn from this specification"""
        provided_account = specification.get("account", "")
        if provided_account:
            if provided_account not in self.amazon.accounts:
                raise BadPolicy("Unknown account specified", account=provided_account, specification=specification)
            else:
                account_id = self.amazon.accounts[provided_account]
        else:
            account_id = self.amazon.account_id

        users = specification.get("users", [])
        for name in listified(specification, "iam"):
            if name == "__self__":
                account_id = self.amazon.account_id
                name = "role/{0}".format(self.name)

            spec = "arn:aws:iam::{0}:{1}".format(account_id, name)
            if not users:
                yield spec
            else:
                for user in users:
                    yield "{0}/{1}".format(spec, user)

    def make_trust_document(self, trust, distrust):
        """Make a document for trust or None if no trust or distrust"""
        if not trust and not distrust:
            return

        statement = {"Sid": "", "Action": "sts:AssumeRole", "Effect": "Allow"}

        if trust:
            statement["Principal"] = {}
            for k, v in trust.items():
                if isinstance(v, list) and len(v) is 1:
                    v = v[0]
                statement["Principal"][k] = v

        if distrust:
            statement["NotPrincipal"] = {}
            for k, v in distrust.items():
                if isinstance(v, list) and len(v) is 1:
                    v = v[0]
                statement["NotPrincipal"][k] = v

        return self.make_document([statement])

    def make_permission_document(self, permissions):
        """Return a document for these permissions, or None if no permissiosn"""
        if not permissions:
            return
        return self.make_document(permissions)

    def make_document(self, statements):
        """Make sure our document is valid and return it formatted correctly"""
        if not isinstance(statements, list):
            raise Exception("Statements should be a list!: got {0}".format(statements))

        document = {"Version": "2012-10-17", "Statement": statements}

        try:
            return json.dumps(document, indent=2)
        except (TypeError, ValueError) as err:
            raise InvalidDocument("Document wasn't valid json", role=self.name, error=err)

