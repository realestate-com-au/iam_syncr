from iam_syncr.errors import BadRole, CantFindTemplate, NoTemplates
from iam_syncr.amazon.roles import AmazonRoles
from iam_syncr.statements import Statements
from iam_syncr.helpers import listified

from option_merge import MergedOptions
import logging
import six

log = logging.getLogger("iam_syncr.roles")

class RoleRemoval(object):
    def __init__(self, name, amazon, templates=None):
        self.name = name
        self.amazon = amazon
        self.templates = templates

    def setup(self):
        """Make sure our name is a string"""
        if not isinstance(self.name, six.string_types):
            raise BadRole("Told to remove a role, but not specified as a string", name=self.name, found_type=type(self.name))

    def resolve(self):
        """Remove the role"""
        AmazonRoles(self.amazon).remove_role(self.name)

class Role(object):
    def __init__(self, name, definition, amazon, templates=None):
        self.name = name
        self.templates = templates
        self.definition = definition
        self.statements = Statements(name, "role", amazon.account_id, amazon.accounts)
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
            self.trust.extend(self.statements.expand_trust_statement(statement, allow=True))

        for statement in listified(self.definition, "disallow_to_assume_me"):
            self.distrust.extend(self.statements.expand_trust_statement(statement, allow=False))

        for key, default_allow in (("permission", None), ("allow_permission", True), ("deny_permission", False)):
            for policy in listified(self.definition, key):
                for statement in self.statements.make_permission_statements(policy, allow=default_allow):
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

    def make_trust_document(self, trust, distrust):
        """Make a document for trust or None if no trust or distrust"""
        if not trust and not distrust:
            return

        return self.statements.make_document((trust or []) + (distrust or []))

    def make_permission_document(self, permissions):
        """Return a document for these permissions, or None if no permissiosn"""
        if not permissions:
            return
        return self.statements.make_document(permissions)

