from iam_syncr.errors import SyncrError, BadAmazon

from boto.iam.connection import IAMConnection
from contextlib import contextmanager
import logging
import urllib
import json
import boto
import sys

log = logging.getLogger("iam_syncr.amazon")

class LeaveAlone(object):
    """Used to differentiate between None and not specified in a call signature"""

class Amazon(object):

    # Account info that is overridden by __init__
    accounts = None
    account_id = None
    account_name = None

    @classmethod
    def set_boto_useragent(self, app_name, version):
        """Put this app in the useragent used by boto"""
        __import__("boto")
        useragent = sys.modules["boto.connection"].UserAgent
        if app_name not in useragent:
            sys.modules["boto.connection"].UserAgent = "{0} {1}/{2}".format(useragent, app_name, version)

    def __init__(self, account_id, account_name, accounts):
        self.changes = False
        self.accounts = accounts
        self.account_id = account_id
        self.account_name = account_name

    def setup(self):
        """Make sure our current credentials are for this account and set self.connection"""
        try:
            connection = IAMConnection()
        except boto.exception.NoAuthHandlerFound:
            raise SyncrError("Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY before running this script (your aws credentials)")

        try:
            result = connection.get_user()
        except boto.exception.BotoServerError as error:
            if error.status == 403:
                raise SyncrError("Your credentials aren't allowed to look at iam :(")
            else:
                raise

        amazon_account_id = result["get_user_response"]["get_user_result"]["user"]["arn"].split(":")[4]
        if str(self.account_id) != str(amazon_account_id):
            raise SyncrError("Please use credentials for the right account", expect=self.account_id, got=amazon_account_id)

        # If reached this far, the credentials belong to the correct account :)
        self.connection = connection
        return connection

    @contextmanager
    def catch_boto_400(self, heading, document, message, **info):
        """Turn a BotoServerError 400 into a BadAmazon"""
        try:
            yield
        except boto.exception.BotoServerError as error:
            if error.status == 400:
                print("=" * 80)
                print(heading)
                print(document)
                print("=" * 80)
                raise BadAmazon(message, error_code=error.code, error_message=error.message, **info)
            else:
                raise

    def role_info(self, name):
        """Return what amazon knows about this role"""
        try:
            return self.connection.get_role(name)["get_role_response"]["get_role_result"]
        except boto.exception.BotoServerError as error:
            if error.status == 404:
                return False
            raise

    def has_role(self, name):
        """Return whether amazon has info about this role"""
        return bool(self.role_info(name))

    def info_for_profile(self, name):
        """Return what roles are attached to this profile if it exists"""
        result = self.connection.list_instance_profiles_for_role(name)
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
        existing_roles_in_profile = self.info_for_profile(name)
        if existing_roles_in_profile is None:
            try:
                log.info("Making instance profile\tname=%s", name)
                self.connection.create_instance_profile(name)
                self.changes = True
            except boto.exception.BotoServerError as error:
                if error.status == 409 and error.code == "EntityAlreadyExists":
                    # I'd rather ignore this conflict, than list all the instance_profiles
                    # Basically, the instance exists but isn't associated with the role
                    pass
                else:
                    raise

        if existing_roles_in_profile and any(rl != name for rl in existing_roles_in_profile):
            for role in [rl for rl in existing_roles_in_profile if rl != name]:
                log.info("Removing role from existing instance_profile\tprofile=%s\trole=%s", name, role)
                self.connection.remove_role_from_instance_profile(name, role)
                self.changes = True

        if not existing_roles_in_profile or not any(rl == name for rl in existing_roles_in_profile):
            log.info("Adding role to an instance_profile\tprofile=%s\trole=%s", name, name)
            self.connection.add_role_to_instance_profile(name, name)
            self.changes = True

    def create_role(self, name, trust_document, policies=None):
        """Create a role"""
        with self.catch_boto_400("{0} trust document".format(name), trust_document, "Couldn't create role", role=name):
            log.info("Creating a new role\trole=%s", self.name)
            self.connection.create_role(name, assume_role_policy_document=trust_document)
            self.changes = True

        # And add our permissions
        if policies:
            for policy_name, document in policies.items():
                if document:
                    with self.catch_boto_400("{0} - {1} Permission document".format(name, policy_name), document, "Couldn't add policy", role=name, policy_name=policy_name):
                        self.connection.put_role_policy(name, policy_name, document)
                        self.changes = True

    def compare_trust_document(self, role_info, trust_document):
        """Say whether the provided trust document is the same as the one in the role_info"""
        if not role_info or not role_info.get("role", {}).get("assume_role_policy_document"):
            return False

        unquoted = urllib.unquote(role_info["role"]["assume_role_policy_document"])
        return self.compare_two_documents(unquoted, trust_document)

    def compare_two_documents(self, doc1, doc2):
        """Compare two documents by converting them into json objects and back to strings and compare"""
        try:
            first = json.dumps(json.loads(doc1), indent=2, sort_keys=True).strip()
        except (ValueError, TypeError):
            return False

        try:
            second = json.dumps(json.loads(doc2), indent=2, sort_keys=True).strip()
        except (ValueError, TypeError):
            return False

        return first == second

    def modify_role(self, role_info, name, trust_document, policies=LeaveAlone):
        """Modify a role"""
        if trust_document and not self.compare_trust_document(role_info, trust_document):
            with self.catch_boto_400("{0} assume document".format(name), trust_document, "Couldn't modify trust document", role=name):
                log.info("Modifying trust document\trole=%s", name)
                self.connection.update_assume_role_policy(name, trust_document)
                self.changes = True

        if policies is LeaveAlone:
            return
        elif policies is None:
            policies = {}

        unknown = []
        current_policies = self.current_role_policies(name, comparing=[pn for pn in policies])
        unknown = [key for key in current_policies if key not in policies]

        if unknown:
            log.info("Role has unknown policies that will be disassociated\trole=%s\tunknown=%s", name, unknown)
            for policy in unknown:
                self.connection.delete_role_policy(name, policy)
                self.changes = True

        for policy, document in policies.items():
            if not document:
                if policy in current_policies:
                    log.info("Removing policy\trole=%s\tpolicy=%s", name, policy)
                    self.connection.delete_role_policy(name, policy)
                    self.changes = True
            else:
                needed = False
                if policy in current_policies:
                    if not self.compare_two_documents(current_policies.get(policy), document):
                        log.info("Overriding existing policy\trole=%s\tpolicy=%s", name, policy)
                        needed = True
                else:
                    log.info("Adding policy to existing role\trole=%s\tpolicy=%s", name, policy)
                    needed = True

                if needed:
                    with self.catch_boto_400("{0} - {1} policy document".format(name, policy), document, "Couldn't add policy document", role=name, policy=policy):
                        self.connection.put_role_policy(name, policy, document)
                        log.debug(policy)
                        log.debug(document)
                        log.debug('------')

    def current_role_policies(self, name, comparing):
        """Get the current policies for some role"""
        policies = self.connection.list_role_policies(name)["list_role_policies_response"]["list_role_policies_result"]["policy_names"]

        found = {}
        for policy in policies:
            document = None
            if policy in comparing:
                doc = self.connection.get_role_policy(name, policy)["get_role_policy_response"]["get_role_policy_result"]["policy_document"]
                document = json.dumps(json.loads(urllib.unquote(doc)), indent=2).strip()
            found[policy] = document

        return found

    def remove_role(self, name):
        """Remove the role if it exists"""
        if self.has_role(name):
            log.info("Deleting role\trole=%s", name)
            self.connection.delete_role(name)
            self.changes = True
        else:
            log.info("Role already deleted\trole=%s", name)

