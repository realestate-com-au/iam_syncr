from iam_syncr.errors import InvalidDocument, BadPolicy, ProgrammerError
from iam_syncr.helpers import listify, listified, as_list

import logging
import json
import six

log = logging.getLogger("iam_syncr.roles")

class Statements(object):
    def __init__(self, name, self_type, account_id, accounts, location=None):
        self.name = name
        self.location = location
        self.self_type = self_type
        if self_type not in ("role", "bucket", "key"):
            raise ProgrammerError("Statements can only be instantiated with self_type of role or bucket or key\tgot={0}".format(self_type))

        self.accounts = accounts
        self.account_id = account_id

    def expand_trust_statement(self, statement, allow=False):
        """Make a trust statement"""
        result = dict((key, val) for key, val in statement.items() if key[0].isupper())
        principal = "principal" if allow else "notprincipal"
        self.expand_principal({principal: statement}, result)

        if "Action" not in result:
            result["Action"] = "sts:AssumeRole"

        if "Effect" not in result:
            result["Effect"] = "Allow"

        if "Sid" not in result:
            result["Sid"] = ""

        yield result

    def expand_principal(self, statement, result):
        """Expand out Principal and NotPrincipal"""
        for principal, capd in [("principal", "Principal"), ("notprincipal", "NotPrincipal")]:
            if principal in statement:
                if capd not in result:
                    result[capd] = {}

                looking_at = statement[principal]
                if not isinstance(looking_at, list):
                    looking_at = [looking_at]

                for instruction in looking_at:
                    principal = result[capd]

                    for specified in listified(instruction, "service"):
                        if specified == "ec2":
                            specified = "ec2.amazonaws.com"
                        listify(principal, "Service").append(specified)

                    for specified in listified(instruction, "federated"):
                        listify(principal, "Federated").extend(self.iam_arns_from_specification(specified))
                        if "Action" not in result:
                            result["Action"] = "sts:AssumeRoleWithSAML"

                    if "iam" in instruction:
                        listify(principal, "AWS").extend(self.iam_arns_from_specification(instruction))

        # Amazon gets rid of the lists if only one item
        # And this mucks around with the diffing....
        for princ in (result.get("Principal"), result.get("NotPrincipal")):
            if princ:
                for principal_type in ("AWS", "Federated", "Service"):
                    if principal_type in princ:
                        if len(listify(princ, principal_type)) == 1:
                            princ[principal_type] = princ[principal_type][0]
                        else:
                            princ[principal_type] = sorted(princ[principal_type])

    def make_permission_statements(self, policy, allow=None):
        """
        Make zero or more permissions statements from a policy definition

        If allow is None and no allow or Effect is specified, an error is raised
        Otherwise we assume the truthiness of allow
        """
        result = dict((key, val) for key, val in policy.items() if key[0].isupper())

        if allow is None and "Effect" not in policy:
            if not isinstance(policy.get("allow"), bool):
                raise BadPolicy("Need to specify whether we allow this policy or not", policy=policy, **{self.self_type:self.name})
            result["Effect"] = ["Deny", "Allow"][policy["allow"]]
        elif allow is not None:
            result["Effect"] = ["Deny", "Allow"][allow]

        for key, dest in (("action", "Action"), ("notaction", "NotAction")):
            for specified in listified(policy, key):
                listify(result, dest).append(specified)

        for key, dest in (("resource", "Resource"), ("notresource", "NotResource")):
            for specified in listified(policy, key):
                listify(result, dest).extend(self.fill_out_resources(specified))

        self.expand_principal(policy, result)

        if "Resource" not in result and "NotResource" not in result:
            raise BadPolicy("No Resource or NotResource was defined for policy", policy=policy, **{self.self_type:self.name})

        if "Action" not in result and "NotAction" not in result:
            raise BadPolicy("No Action or NotAction defined for this policy", policy=policy, **{self.self_type:self.name})

        if "Sid" not in result and self.self_type == "bucket":
            result["Sid"] = ""

        # Amazon gets rid of the lists if only one item
        # And this mucks around with the diffing....
        for thing in ("Action", "NotAction", "Resource", "NotResource"):
            if thing in result:
                if len(listify(result, thing)) == 1:
                    result[thing] = result[thing][0]
                else:
                    result[thing] = sorted(result[thing])

        yield result

    def fill_out_resources(self, resources):
        """Fill out the resources"""
        for resource in as_list(resources):
            if isinstance(resource, six.string_types):
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

        elif "kms" in resource:
            for found in self.kms_arns_from_specification(resource):
                yield found

        elif "sns" in resource:
            for found in self.sns_arns_from_specification(resource):
                yield found

        elif "s3" in resource:
            for bucket_key in listify(resource, "s3"):
                if bucket_key == "__self__":
                    if self.self_type == "role":
                        raise BadPolicy("Role policy has no __self__ bucket", role=self.name)
                    elif self.self_type == "key":
                        raise BadPolicy("Key policy has no __self__ bucket", key=self.name)
                    else:
                        bucket_key = self.name
                yield "arn:aws:s3:::{0}".format(bucket_key)
                if '/' not in bucket_key:
                    yield "arn:aws:s3:::{0}/*".format(bucket_key)

        else:
            raise BadPolicy("Unknown resource type", resource=resource)

    def sns_arns_from_specification(self, resource):
        """Get us kms arns from this specification"""
        for key_id in listify(resource, "sns"):
            location = self.location
            if 'location' in resource:
                location = resource['location']

            provided_accounts = resource.get("account", "")
            if not isinstance(provided_accounts, list):
                provided_accounts = [provided_accounts]

            for provided_account in provided_accounts:
                if provided_account:
                    if provided_account not in self.accounts:
                        raise BadPolicy("Unknown account specified", account=provided_account, specification=resource)
                    else:
                        account_id = self.accounts[provided_account]
                else:
                    account_id = self.account_id

                yield "arn:aws:sns:{0}:{1}:{2}".format(location, account_id, key_id)


    def kms_arns_from_specification(self, resource):
        """Get us kms arns from this specification"""
        for key_id in listify(resource, "kms"):
            alias = None
            if key_id == "__self__":
                if self.self_type != "key":
                    raise BadPolicy("No __self__ key for this policy", type=self.self_type, name=self.name)
                else:
                    alias = self.name
                    location = self.location

            if not alias:
                if isinstance(key_id, six.string_types):
                    alias = key_id
                    location = resource.get("location", self.location)
                else:
                    alias = key_id.get("alias")
                    location = key_id.get("location", resource.get("location", self.location))
                    key_id = key_id.get("key_id")

            provided_accounts = resource.get("account", "")
            if not isinstance(provided_accounts, list):
                provided_accounts = [provided_accounts]

            for provided_account in provided_accounts:
                if provided_account:
                    if provided_account not in self.accounts:
                        raise BadPolicy("Unknown account specified", account=provided_account, specification=resource)
                    else:
                        account_id = self.accounts[provided_account]
                else:
                    account_id = self.account_id

                if alias:
                    yield "arn:aws:kms:{0}:{1}:alias/{2}".format(location, account_id, alias)
                else:
                    yield "arn:aws:kms:{0}:{1}:key/{2}".format(location, account_id, key_id)

    def iam_arns_from_specification(self, specification):
        """Get us an iam arn from this specification"""
        if not isinstance(specification, list):
            specification = [specification]

        for spec in specification:
            if isinstance(spec, six.string_types):
                yield spec
            else:
                provided_accounts = spec.get("account", "")
                if not isinstance(provided_accounts, list):
                    provided_accounts = [provided_accounts]

                for provided_account in provided_accounts:
                    if provided_account:
                        if provided_account not in self.accounts:
                            raise BadPolicy("Unknown account specified", account=provided_account, specification=spec)
                        else:
                            account_id = self.accounts[provided_account]
                    else:
                        account_id = self.account_id

                    users = spec.get("users", [])
                    for name in listified(spec, "iam"):
                        if name == "__self__":
                            if self.self_type == 'bucket':
                                raise BadPolicy("Bucket policy has no __self__ iam role", bucket=self.name)

                            account_id = self.account_id
                            name = "role/{0}".format(self.name)

                        service = "sts" if name.startswith("assumed-role") else "iam"
                        arn = "arn:aws:{0}::{1}:{2}".format(service, account_id, name)
                        if not users:
                            yield arn
                        else:
                            for user in users:
                                yield "{0}/{1}".format(arn, user)

    def make_document(self, statements):
        """Make sure our document is valid and return it formatted correctly"""
        if not isinstance(statements, list):
            raise Exception("Statements should be a list!: got {0}".format(statements))

        document = {"Version": "2012-10-17", "Statement": statements}

        try:
            return json.dumps(document, indent=2)
        except (TypeError, ValueError) as err:
            raise InvalidDocument("Document wasn't valid json", error=err, **{self.self_type:self.name})

