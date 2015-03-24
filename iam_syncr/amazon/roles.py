from iam_syncr.amazon.common import AmazonMixin, LeaveAlone
from iam_syncr.amazon.documents import AmazonDocuments

from six.moves.urllib import parse
import logging
import boto
import json

log = logging.getLogger("iam_syncr.amazon.roles")

class AmazonRoles(AmazonMixin, object):
    def __init__(self, amazon):
        self.amazon = amazon
        self.documents = AmazonDocuments()
        self.connection = amazon.connection

    def split_role_name(self, name):
        """Split a role name into it's (name, path)"""
        split = name.split('/')
        role_name = split[-1]
        path = '/'.join(split[0:-1]) or None
        if path and not path.startswith('/'):
            path = "/{0}".format(path)
        if path and not path.endswith("/"):
            path = "{0}/".format(path)
        return role_name, path

    def role_info(self, name):
        """Return what amazon knows about this role"""
        try:
            role_name, _ = self.split_role_name(name)
            return self.connection.get_role(role_name)["get_role_response"]["get_role_result"]
        except boto.exception.BotoServerError as error:
            if error.status == 404:
                return False
            raise

    def has_role(self, name):
        """Return whether amazon has info about this role"""
        return bool(self.role_info(name))

    def info_for_profile(self, name):
        """Return what roles are attached to this profile if it exists"""
        profiles = []
        role_name, _ = self.split_role_name(name)
        with self.ignore_boto_404():
            with self.catch_boto_400("Couldn't list instance profiles associated with a role", role=role_name):
                result = self.connection.list_instance_profiles_for_role(role_name)
            profiles = result["list_instance_profiles_for_role_response"]["list_instance_profiles_for_role_result"]["instance_profiles"]

        existing_profile = None
        for profile in profiles:
            if profile["instance_profile_name"] == name:
                existing_profile = profile
                break

        if existing_profile:
            if "member" in existing_profile["roles"]:
                return [existing_profile["roles"]["member"]["role_name"]]
            else:
                return []

    def make_instance_profile(self, name):
        """Make an instance profile with this name containing this role"""
        role_name, _ = self.split_role_name(name)
        existing_roles_in_profile = self.info_for_profile(role_name)
        if existing_roles_in_profile is None:
            try:
                with self.catch_boto_400("Couldn't create instance profile", instance_profile=role_name):
                    for _ in self.change("+", "instance_profile", profile=role_name):
                        self.connection.create_instance_profile(role_name)
            except boto.exception.BotoServerError as error:
                if error.status == 409 and error.code == "EntityAlreadyExists":
                    # I'd rather ignore this conflict, than list all the instance_profiles
                    # Basically, the instance exists but isn't associated with the role
                    pass
                else:
                    raise

        if existing_roles_in_profile and any(rl != role_name for rl in existing_roles_in_profile):
            for role in [rl for rl in existing_roles_in_profile if rl != role_name]:
                with self.catch_boto_400("Couldn't remove role from an instance profile", profile=role_name, role=role):
                    for _ in self.change("-", "instance_profile_role", profile=role_name, role=role):
                        self.connection.remove_role_from_instance_profile(role_name, role)

        if not existing_roles_in_profile or not any(rl == role_name for rl in existing_roles_in_profile):
            with self.catch_boto_400("Couldn't add role to an instance profile", role=role_name, instance_profile=role_name):
                for _ in self.change("+", "instance_profile_role", profile=role_name, role=role_name):
                    self.connection.add_role_to_instance_profile(role_name, role_name)

    def create_role(self, name, trust_document, policies=None):
        """Create a role"""
        role_name, role_path = self.split_role_name(name)
        with self.catch_boto_400("Couldn't create role", "{0} trust document".format(name), trust_document, role=name):
            for _ in self.change("+", "role", role=role_name, document=trust_document):
                self.connection.create_role(role_name, assume_role_policy_document=trust_document, path=role_path)

        # And add our permissions
        if policies:
            for policy_name, document in policies.items():
                if document:
                    with self.catch_boto_400("Couldn't add policy", "{0} - {1} Permission document".format(role_name, policy_name), document, role=role_name, policy_name=policy_name):
                        for _ in self.change("+", "role_policy", role=role_name, policy=policy_name, document=document):
                            self.connection.put_role_policy(role_name, policy_name, document)

    def modify_role(self, role_info, name, trust_document, policies=LeaveAlone):
        """Modify a role"""
        role_name, _ = self.split_role_name(name)
        if trust_document:
            changes = list(self.documents.compare_trust_document(role_info, trust_document))
            if changes:
                with self.catch_boto_400("Couldn't modify trust document", "{0} assume document".format(role_name), trust_document, role=role_name):
                    for _ in self.change("M", "trust_document", role=role_name, changes=changes):
                        self.connection.update_assume_role_policy(role_name, trust_document)

        if policies is LeaveAlone:
            return
        elif policies is None:
            policies = {}

        unknown = []
        with self.catch_boto_400("Couldn't get policies for a role", role=role_name):
            current_policies = self.current_role_policies(role_name, comparing=[pn for pn in policies])
        unknown = [key for key in current_policies if key not in policies]

        if unknown:
            log.info("Role has unknown policies that will be disassociated\trole=%s\tunknown=%s", role_name, unknown)
            for policy in unknown:
                with self.catch_boto_400("Couldn't delete a policy from a role", policy=policy, role=role_name):
                    for _ in self.change("-", "role_policy", role=role_name, policy=policy):
                        self.connection.delete_role_policy(role_name, policy)

        for policy, document in policies.items():
            if not document:
                if policy in current_policies:
                    with self.catch_boto_400("Couldn't delete a policy from a role", policy=policy, role=role_name):
                        for _ in self.change("-", "policy", role=role_name, policy=policy):
                            self.connection.delete_role_policy(role_name, policy)
            else:
                needed = False
                changes = None

                if policy in current_policies:
                    changes = list(self.documents.compare_two_documents(current_policies.get(policy), document))
                    if changes:
                        log.info("Overriding existing policy\trole=%s\tpolicy=%s", role_name, policy)
                        needed = True
                else:
                    log.info("Adding policy to existing role\trole=%s\tpolicy=%s", role_name, policy)
                    needed = True

                if needed:
                    with self.catch_boto_400("Couldn't add policy document", "{0} - {1} policy document".format(role_name, policy), document, role=role_name, policy=policy):
                        symbol = "M" if changes else "+"
                        for _ in self.change(symbol, "role_policy", role=role_name, policy=policy, changes=changes, document=document):
                            self.connection.put_role_policy(role_name, policy, document)

    def current_role_policies(self, name, comparing):
        """Get the current policies for some role"""
        role_name, _ = self.split_role_name(name)
        with self.catch_boto_400("Couldn't get policies for a role", role=name):
            policies = self.connection.list_role_policies(role_name)["list_role_policies_response"]["list_role_policies_result"]["policy_names"]

        found = {}
        for policy in policies:
            document = None
            if policy in comparing:
                with self.catch_boto_400("Couldn't get policy document for some policy", policy=policy, role=name):
                    doc = self.connection.get_role_policy(role_name, policy)["get_role_policy_response"]["get_role_policy_result"]["policy_document"]
                document = json.dumps(json.loads(parse.unquote(doc)), indent=2).strip()
            found[policy] = document

        return found

    def remove_role(self, name):
        """Remove the role if it exists"""
        role_name, _ = self.split_role_name(name)
        if self.has_role(role_name):
            with self.catch_boto_400("Couldn't get policies for a role", role=role_name):
                current_policies = self.current_role_policies(role_name, comparing=[])

            for policy in current_policies:
                with self.catch_boto_400("Couldn't delete a policy from a role", policy=policy, role=role_name):
                    for _ in self.change("-", "policy", role=role_name, policy=policy):
                        self.connection.delete_role_policy(role_name, policy)

            with self.catch_boto_400("Couldn't delete a role", role=role_name):
                for _ in self.change("-", "role", role=role_name):
                    self.connection.delete_role(role_name)
        else:
            log.info("Role already deleted\trole=%s", role_name)

