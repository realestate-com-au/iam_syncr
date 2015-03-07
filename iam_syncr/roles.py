from iam_syncr.errors import InvalidDocument, BadRole, BadPolicy, CantFindTemplate, NoTemplates
from iam_syncr.helpers import listify, listified, as_list
from iam_syncr.amazon.roles import AmazonRoles

from option_merge import MergedOptions
import logging
import json
import six

log = logging.getLogger("iam_syncr.roles")

class RoleRemoval(object):
    def __init__(self, name, amazon, templates=None):
        self.name = name
        self.amazon = amazon
        self.templates = templates

    def setup(self):
        """Make sure our name is a string"""
        if not isinstance(self.name, basestring):
            raise BadRole("Told to remove a role, but not specified as a string", name=self.name, found_type=type(self.name))

    def resolve(self):
        """Remove the role"""
        AmazonRoles(self.amazon).remove_role(self.name)

class Role(object):
    def __init__(self, name, definition, amazon, templates=None):
        self.name = name
        self.templates = templates
        self.definition = definition
        self.policy_name = "syncr_policy_{0}".format(self.name.replace("/", "__"))

        self.amazon = amazon
        self.amazon_roles = AmazonRoles(amazon)

        self.trust = []
        self.distrust = []
        self.permission = []

    def setup(self):
        """Raise errors if the definition doesn't make sense"""
        if "use" in self.definition:
            template = self.definition["use"]
            if not self.templates:
                raise NoTemplates(name=self.name, looking_for_template=template, available=self.templates.keys())

            if template not in self.templates:
                raise CantFindTemplate(name=self.name, looking_for_template=template, available=self.templates.keys())

            self.definition = MergedOptions.using(self.templates[template], self.definition)

        self.description = self.definition.get("description", "No description provided!")

        for statement in listified(self.definition, "allow_to_assume_me"):
            self.trust.extend(self.expand_trust_statement(statement, allow=True))

        for statement in listified(self.definition, "disallow_to_assume_me"):
            self.distrust.extend(self.expand_trust_statement(statement, allow=False))

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

        role_info = self.amazon_roles.role_info(self.name)
        if not role_info:
            self.amazon_roles.create_role(self.name, trust_document, policies={self.policy_name: permission_document})
        else:
            self.amazon_roles.modify_role(role_info, self.name, trust_document, policies={self.policy_name: permission_document})

        if self.definition.get("make_instance_profile"):
            self.amazon_roles.make_instance_profile(self.name)

    def expand_trust_statement(self, statement, allow=False):
        """Make a trust statement"""
        result = dict((key, val) for key, val in statement.items() if key[0].isupper())

        if allow and "Principal" not in result:
            result["Principal"] = {}
            principal = result["Principal"]

        if not allow and "NotPrincipal" not in result:
            result["NotPrincipal"] = {}
            principal = result["NotPrincipal"]

        for specified in listified(statement, "service"):
            if specified == "ec2":
                specified = "ec2.amazonaws.com"
            listify(principal, "Service").append(specified)

        for specified in listified(statement, "federated"):
            listify(principal, "Federated").extend(self.iam_arns_from_specification(specified))
            if "Action" not in result:
                result["Action"] = "sts:AssumeRoleWithSAML"

        if "iam" in statement:
            listify(principal, "AWS").extend(self.iam_arns_from_specification(statement))

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

        if "Action" not in result:
            result["Action"] = "sts:AssumeRole"

        if "Effect" not in result:
            result["Effect"] = "Allow"

        if "Sid" not in result:
            result["Sid"] = ""

        yield result

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
        if not isinstance(specification, list):
            specification = [specification]

        for spec in specification:
            if isinstance(spec, six.string_types):
                yield spec
            else:
                provided_account = spec.get("account", "")
                if provided_account:
                    if provided_account not in self.amazon.accounts:
                        raise BadPolicy("Unknown account specified", account=provided_account, specification=spec)
                    else:
                        account_id = self.amazon.accounts[provided_account]
                else:
                    account_id = self.amazon.account_id

                users = spec.get("users", [])
                for name in listified(spec, "iam"):
                    if name == "__self__":
                        account_id = self.amazon.account_id
                        name = "role/{0}".format(self.name)

                    service = "sts" if name.startswith("assumed-role") else "iam"
                    spec = "arn:aws:{0}::{1}:{2}".format(service, account_id, name)
                    if not users:
                        yield spec
                    else:
                        for user in users:
                            yield "{0}/{1}".format(spec, user)

    def make_trust_document(self, trust, distrust):
        """Make a document for trust or None if no trust or distrust"""
        if not trust and not distrust:
            return

        return self.make_document((trust or []) + (distrust or []))

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

