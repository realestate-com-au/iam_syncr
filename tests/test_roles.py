# coding: spec

from iam_syncr.errors import BadRole, BadPolicy, InvalidDocument
from iam_syncr.amazon.roles import AmazonRoles
from iam_syncr.roles import RoleRemoval, Role
from iam_syncr.amazon.base import Amazon

from noseOfYeti.tokeniser.support import noy_sup_setUp
from textwrap import dedent
import uuid
import mock

from tests.helpers import TestCase

describe TestCase, "RoleRemoval":
    before_each:
        self.name = mock.Mock(name="name")
        self.amazon = mock.create_autospec(spec=Amazon, instance=True, spec_set=True, dry_run=False)

    it "has a name and amazon object":
        name = mock.Mock(name="name")
        amazon = mock.Mock(name="amazon")
        roleremoval = RoleRemoval(name, amazon)
        self.assertIs(roleremoval.name, name)
        self.assertIs(roleremoval.amazon, amazon)

    describe "Setup":
        it "complains if the name isn't a string":
            for name in (0, 1, True, False, None, [], [1], {}, {1:2}, lambda: 1, mock.Mock(name="mock")):
                with self.assertRaisesRegexp(BadRole, "Told to remove a role, but not specified as a string.+"):
                    RoleRemoval(name, self.amazon).setup()

    describe "Resolving":
        it "asks amazon to remove the role":
            remove_role = mock.Mock(name="remove_role")
            with mock.patch.object(AmazonRoles, "remove_role", remove_role):
                RoleRemoval(self.name, self.amazon).resolve()
            remove_role.assert_called_once_with(self.name)

describe TestCase, "Role":
    before_each:
        self.name = mock.Mock(name="name")
        self.amazon = mock.create_autospec(spec=Amazon, instance=True, spec_set=True, dry_run=False)
        self.definition = mock.Mock(name="definition")

    it "has a name, definition and amazon object; and inits trust, distrust and permission":
        name = mock.Mock(name="name")
        amazon = mock.Mock(name="amazon")
        definition = mock.Mock(name="definition")
        role = Role(name, definition, amazon)
        self.assertIs(role.name, name)
        self.assertIs(role.amazon, amazon)
        self.assertIs(role.definition, definition)

        self.assertEqual(role.trust, [])
        self.assertEqual(role.distrust, [])
        self.assertEqual(role.permission, [])

    describe "Setup":
        it "sets description":
            role = Role(self.name, {}, self.amazon)
            role.setup()
            self.assertEqual(role.description, "No description provided!")

            description = mock.Mock(name="description")
            role = Role(self.name, {"description": description}, self.amazon)
            role.setup()
            self.assertIs(role.description, description)

        it "adds trust and distrust from allow_to_assume_me and disallow_to_assume_me":
            princ1, tprinc1 = mock.Mock(name="princ1"), mock.Mock(name="tprinc1")
            princ2, tprinc2 = mock.Mock(name="princ2"), mock.Mock(name="tprinc2")
            princ3, tprinc3 = mock.Mock(name="princ3"), mock.Mock(name="tprinc3")
            princ4, tprinc4 = mock.Mock(name="princ4"), mock.Mock(name="tprinc4")
            princ5, tprinc5 = mock.Mock(name="princ5"), mock.Mock(name="tprinc5")
            princ6, tprinc6 = mock.Mock(name="princ6"), mock.Mock(name="tprinc6")
            transformed = {
                  princ1:[tprinc1], princ2:[tprinc2], princ3:[tprinc3]
                , princ4:[tprinc4], princ5:[tprinc5], princ6:[tprinc6]
                }

            allow_to_assume_me = [princ1, princ2, princ3]
            disallow_to_assume_me = [princ4, princ5, princ6]
            fake_expand_trust_statement = mock.Mock(name="expand_trust_statement")
            fake_expand_trust_statement.side_effect = lambda princ, allow=False: transformed[princ]

            # With lists of principals
            role = Role(self.name, {"allow_to_assume_me": allow_to_assume_me, "disallow_to_assume_me": disallow_to_assume_me}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role, "expand_trust_statement", fake_expand_trust_statement):
                role.setup()
            self.assertSortedEqual(role.trust, [tprinc1, tprinc2, tprinc3])
            self.assertSortedEqual(role.distrust, [tprinc4, tprinc6, tprinc5])

            # And not giving lists
            role = Role(self.name, {"allow_to_assume_me": princ1, "disallow_to_assume_me": princ2}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role, "expand_trust_statement", fake_expand_trust_statement):
                role.setup()
            self.assertSortedEqual(role.trust, [tprinc1])
            self.assertSortedEqual(role.distrust, [tprinc2])

            # And with only allow
            role = Role(self.name, {"allow_to_assume_me": princ1}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role, "expand_trust_statement", fake_expand_trust_statement):
                role.setup()
            self.assertSortedEqual(role.trust, [tprinc1])
            self.assertSortedEqual(role.distrust, {})

        it "adds permissions from permission, allow_permission and deny_permission":
            pol1, tpol1 = mock.Mock(name="pol1"), mock.Mock(name="tpol1")
            pol1b, tpol1b = mock.Mock(name="pol1b"), mock.Mock(name="tpol1b")

            pol2, tpol2 = mock.Mock(name="pol2"), mock.Mock(name="tpol2")
            pol3, tpol3 = mock.Mock(name="pol3"), mock.Mock(name="tpol3")
            pol4, tpol4 = mock.Mock(name="pol4"), mock.Mock(name="tpol4")
            pol5, tpol5 = mock.Mock(name="pol5"), mock.Mock(name="tpol5")
            pol6, tpol6 = mock.Mock(name="pol6"), mock.Mock(name="tpol6")
            transformed = {
                  pol1:[tpol1, tpol1b], pol2:[tpol2], pol3:[tpol3]
                , pol4:[tpol4], pol5:[tpol5], pol6:[tpol6]
                }

            permission = [pol3]
            allow_permission = [pol1, pol2]
            deny_permission = [pol4, pol5, pol6]
            fake_make_permission_statements = mock.Mock(name="make_permission_statements")
            fake_make_permission_statements.side_effect = lambda pol, allow: [(p, allow) for p in transformed[pol]]

            # With lists of polipals
            role = Role(self.name, {"allow_permission": allow_permission, "deny_permission": deny_permission, "permission": permission}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role, "make_permission_statements", fake_make_permission_statements):
                role.setup()
            self.assertEqual(role.permission, [(tpol3, None), (tpol1, True), (tpol1b, True), (tpol2, True), (tpol4, False), (tpol5, False), (tpol6, False)])

            # And not giving lists
            role = Role(self.name, {"allow_permission": pol1, "deny_permission": pol2, "permission": pol3}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role, "make_permission_statements", fake_make_permission_statements):
                role.setup()
            self.assertEqual(role.permission, [(tpol3, None), (tpol1, True), (tpol1b, True), (tpol2, False)])

            # And with only allow
            role = Role(self.name, {"allow_permission": pol1}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role, "make_permission_statements", fake_make_permission_statements):
                role.setup()
            self.assertEqual(role.permission, [(tpol1, True), (tpol1b, True)])

    describe "Resolving the role":
        before_each:
            self.trust = mock.Mock(name="trust")
            self.distrust = mock.Mock(name="distrust")
            self.permission = mock.Mock(name="permission")
            self.policy_name = mock.Mock(name="policy_name")
            self.trust_document = mock.Mock(name="trust_document")
            self.permission_document = mock.Mock(name="permission_document")
            self.role = Role(self.name, self.definition, self.amazon)

            self.role.trust = self.trust
            self.role.distrust = self.distrust
            self.role.permission = self.permission
            self.role.policy_name = self.policy_name

        describe "When the role doesn't already exist":
            it "creates the role and makes an instance profile if it needs to":
                role_info = mock.Mock(name="remove_role")
                create_role = mock.Mock(name="create_role")
                make_instance_profile = mock.Mock(name="make_instance_profile")

                with mock.patch.multiple(AmazonRoles, role_info=role_info, create_role=create_role, make_instance_profile=make_instance_profile):
                    role_info.return_value = False

                    fake_make_trust_document = mock.Mock(name="make_trust_document")
                    fake_make_trust_document.return_value = self.trust_document

                    fake_make_permission_document = mock.Mock(name="make_permission_document")
                    fake_make_permission_document.return_value = self.permission_document

                    called = []
                    create_role.side_effect = lambda *args, **kwargs: called.append(1)
                    make_instance_profile.side_effect = lambda *args, **kwargs: called.append(2)

                    with mock.patch.multiple(self.role, make_trust_document=fake_make_trust_document, make_permission_document=fake_make_permission_document):
                        self.role.resolve()
                    create_role.assert_called_once_with(self.name, self.trust_document, policies={self.policy_name: self.permission_document})
                    make_instance_profile.assert_called_once_with(self.name)
                    self.assertEqual(called, [1, 2])

        describe "When the role does already exist":
            it "modifies the role and makes an instance profile if it needs to":
                role_info = mock.Mock(name="remove_role")
                modify_role = mock.Mock(name="modify_role")
                make_instance_profile = mock.Mock(name="make_instance_profile")

                with mock.patch.multiple(AmazonRoles, role_info=role_info, modify_role=modify_role, make_instance_profile=make_instance_profile):
                    role_info.return_value = role_info

                    fake_make_trust_document = mock.Mock(name="make_trust_document")
                    fake_make_trust_document.return_value = self.trust_document

                    fake_make_permission_document = mock.Mock(name="make_permission_document")
                    fake_make_permission_document.return_value = self.permission_document

                    called = []
                    modify_role.side_effect = lambda *args, **kwargs: called.append(1)
                    make_instance_profile.side_effect = lambda *args, **kwargs: called.append(2)

                    with mock.patch.multiple(self.role, make_trust_document=fake_make_trust_document, make_permission_document=fake_make_permission_document):
                        self.role.resolve()
                    modify_role.assert_called_once_with(role_info, self.name, self.trust_document, policies={self.policy_name: self.permission_document})
                    make_instance_profile.assert_called_once_with(self.name)
                    self.assertEqual(called, [1, 2])

    describe "Expanding trust statements":
        def statements_from(self, statement, allow=False):
            """Make a Role and use it to normalise a principal"""
            amazon = mock.create_autospec(spec=Amazon, instance=True, spec_set=True, dry_run=False)
            return list(Role(self.name, self.definition, amazon).expand_trust_statement(statement, allow=allow))

        def assertPrincipal(self, statement, expected):
            """Make a trust statement and check the Principal"""
            self.assertEqual(self.statements_from(statement, allow=True), [{"Action": "sts:AssumeRole", "Effect": "Allow", "Sid": "", "Principal": expected}])

        it "sets Principal if allow is True":
            self.assertEqual(self.statements_from({"service": "ec2"}, allow=True), [{"Action": "sts:AssumeRole", "Effect": "Allow", "Sid": "", "Principal": {"Service": "ec2.amazonaws.com"}}])

        it "sets NotPrincipal if allow is False":
            self.assertEqual(self.statements_from({"service": "ec2"}, allow=False), [{"Action": "sts:AssumeRole", "Effect": "Allow", "Sid": "", "NotPrincipal": {"Service": "ec2.amazonaws.com"}}])

        it "sets Federated to iam roles and Action to sts:AssumeRoleWithSAML if using federated iam roles":
            iam_specs = mock.Mock(name="iam_specs")
            transformed_specs = mock.Mock(name="transformed_specs")
            iam_arns_from_specification = mock.Mock(name="iam_arns_from_specification")
            iam_arns_from_specification.return_value = [transformed_specs]

            with mock.patch("iam_syncr.roles.Role.iam_arns_from_specification", iam_arns_from_specification):
                self.assertEqual(self.statements_from({"federated": iam_specs}, allow=True), [{"Action": "sts:AssumeRoleWithSAML", "Effect": "Allow", "Sid": "", "Principal": {"Federated": transformed_specs}}])

            iam_arns_from_specification.assert_called_once_with(iam_specs)

        it "sets AWS to expanded iam_roles":
            iam_specs = mock.Mock(name="iam_specs")
            transformed_specs = mock.Mock(name="transformed_specs")
            iam_arns_from_specification = mock.Mock(name="iam_arns_from_specification")
            iam_arns_from_specification.return_value = [transformed_specs]

            with mock.patch("iam_syncr.roles.Role.iam_arns_from_specification", iam_arns_from_specification):
                self.assertEqual(self.statements_from({"iam": iam_specs}, allow=True), [{"Action": "sts:AssumeRole", "Effect": "Allow", "Sid": "", "Principal": {"AWS": transformed_specs}}])

            iam_arns_from_specification.assert_called_once_with({"iam": iam_specs})

        it "sets Service from service":
            self.assertPrincipal({"service": ["ec2", "blah"]}, {"Service": sorted(["ec2.amazonaws.com", "blah"])})

        it "unlists AWS, Federated and Service":
            self.assertEqual(
                  self.statements_from({"NotPrincipal": {"Service": ['hello']}, "Principal": {"Service": ['what'], "Federated": ["is"], "AWS": ["up"]}}, allow=True)
                , [{"Action": "sts:AssumeRole", "Effect": "Allow", "Sid": "", "NotPrincipal": {"Service": "hello"}, "Principal": {"Service": "what", "Federated": "is", "AWS": "up"}}]
                )

        it "doesn't override Action, Effect or Sid":
            sid = mock.Mock(name="sid")
            action = mock.Mock(name="action")
            effect = mock.Mock(name="effect")

            self.assertEqual(list(self.statements_from({"Effect": effect, "Action": action, "Sid": sid}, allow=True)), [{"Action": action, "Effect": effect, "Sid": sid, "Principal":{}}])

    describe "Making permissions statements":
        def statements_from(self, policy, allow=None, patches=None):
            """Make a Role and use it to normalise a permission policy into a statement"""
            role = Role(self.name, self.definition, self.amazon)
            make_statements = lambda role: sorted(list(role.make_permission_statements(policy, allow=allow)))
            if not patches:
                return make_statements(role)
            else:
                with mock.patch.multiple(role, **patches):
                    return make_statements(role)

        it "passes through capitalised keys as is":
            meh = mock.Mock(name="meh")
            other = mock.Mock(name="other")
            action = mock.Mock(name="action")
            effect = mock.Mock(name="effect")
            resource = mock.Mock(name="resource")

            policy = {"Action": action, "Resource": resource, "Other": other, "meh": meh, "Effect": effect}
            statements = self.statements_from(policy)
            self.assertEqual(statements, [{"Action": action, "Resource": resource, "Other": other, "Effect": effect}])

        it "complains if no Effect is specified":
            with self.assertRaisesRegexp(BadPolicy, "Need to specify whether we allow this policy or not.+"):
                self.statements_from({})

            with self.assertRaisesRegexp(BadPolicy, "No Resource.+"):
                self.statements_from({"Effect": "notchecked"})

            with self.assertRaisesRegexp(BadPolicy, "No Resource.+"):
                self.statements_from({"allow": True})

            with self.assertRaisesRegexp(BadPolicy, "No Resource.+"):
                self.statements_from({}, allow=True)

            with self.assertRaisesRegexp(BadPolicy, "No Resource.+"):
                self.statements_from({}, allow=False)

        it "complains if allow is specified as something that isn't a boolean":
            for allow in (0, 1, None, [], [1], {}, {1:2}, lambda:1, mock.Mock(name="blah")):
                with self.assertRaisesRegexp(BadPolicy, "Need to specify whether we allow this policy or not.+"):
                    self.statements_from({"allow": allow})

        it "sets Effect to Allow or Deny according to what is set":
            def test_effect(allow, expected):
                for statements in (
                      self.statements_from({"allow": allow, "Resource": "blah", "Action": "meh"})
                    , self.statements_from({"Resource": "blah", "Action": "meh"}, allow=allow)
                    ):
                    self.assertEqual(len(statements), 1)
                    assert "Effect" in statements[0], statements
                    self.assertEqual(statements[0]["Effect"], expected)

            test_effect(True, "Allow")
            test_effect(False, "Deny")

        it "sets Action and NotAction from action and notaction":
            for key, dest in (("action", "Action"), ("notaction", "NotAction")):
                policy = {"Resource": "resource", key: "Stuff"}
                self.assertEqual(self.statements_from(policy, allow=True), [{"Effect": "Allow", "Resource": "resource", dest: ["Stuff"]}])
                self.assertEqual(self.statements_from(policy, allow=False), [{"Effect": "Deny", "Resource": "resource", dest: ["Stuff"]}])

                policy = {"Resource": "resource", key: ["Stuff"]}
                self.assertEqual(self.statements_from(policy, allow=True), [{"Effect": "Allow", "Resource": "resource", dest: ["Stuff"]}])
                self.assertEqual(self.statements_from(policy, allow=False), [{"Effect": "Deny", "Resource": "resource", dest: ["Stuff"]}])

                policy = {"Resource": "resource", key: ["Stuff", "otHer:*"]}
                self.assertEqual(self.statements_from(policy, allow=True), [{"Effect": "Allow", "Resource": "resource", dest: ["Stuff", "otHer:*"]}])
                self.assertEqual(self.statements_from(policy, allow=False), [{"Effect": "Deny", "Resource": "resource", dest: ["Stuff", "otHer:*"]}])

        it "sets Resource and NotResource from resource and notresource":
            res1, tres1 = mock.Mock(name="res1"), mock.Mock(name="tres1")
            res2, tres2 = mock.Mock(name="res2"), mock.Mock(name="tres2")
            res3, tres3, tres4 = mock.Mock(name="res3"), mock.Mock(name="tres3"), mock.Mock(name="tres4")

            fake_fill_out_resources = mock.Mock(name="fill_out_resources")
            fake_fill_out_resources.side_effect = lambda res: {res1:[tres1], res2:[tres2], res3:[tres3, tres4]}[res]
            patches = {"fill_out_resources": fake_fill_out_resources}

            for key, dest in (("resource", "Resource"), ("notresource", "NotResource")):
                policy = {"Action": "action", key: res1}
                self.assertEqual(self.statements_from(policy, allow=True, patches=patches), [{"Effect": "Allow", "Action": "action", dest: [tres1]}])
                self.assertEqual(self.statements_from(policy, allow=False, patches=patches), [{"Effect": "Deny", "Action": "action", dest: [tres1]}])

                policy = {"Action": "action", key: [res1]}
                self.assertEqual(self.statements_from(policy, allow=True, patches=patches), [{"Effect": "Allow", "Action": "action", dest: [tres1]}])
                self.assertEqual(self.statements_from(policy, allow=False, patches=patches), [{"Effect": "Deny", "Action": "action", dest: [tres1]}])

                policy = {"Action": "action", key: [res2, res3]}
                self.assertEqual(self.statements_from(policy, allow=True, patches=patches), [{"Effect": "Allow", "Action": "action", dest: [tres2, tres3, tres4]}])
                self.assertEqual(self.statements_from(policy, allow=False, patches=patches), [{"Effect": "Deny", "Action": "action", dest: [tres2, tres3, tres4]}])

        it "complains if no resource gets set":
            with self.assertRaisesRegexp(BadPolicy, "No Resource.+"):
                self.statements_from({}, allow=True)

            with self.assertRaisesRegexp(BadPolicy, "No Action.+"):
                self.statements_from({"resource": "some_arn"}, allow=True)

            with self.assertRaisesRegexp(BadPolicy, "No Action.+"):
                self.statements_from({"notresource": "some_arn"}, allow=False)

            with self.assertRaisesRegexp(BadPolicy, "No Action.+"):
                self.statements_from({"Resource": "some_arn"}, allow=True)

            with self.assertRaisesRegexp(BadPolicy, "No Action.+"):
                self.statements_from({"NotResource": "some_arn"}, allow=False)

        it "complains if no action gets set":
            with self.assertRaisesRegexp(BadPolicy, "No Action.+"):
                self.statements_from({"Resource": "some_arn"}, allow=True)

            assert_works = lambda key, val, expected_key, expected_val: self.assertEqual(
                  self.statements_from({"resource": "some_arn", key:val}, allow=True)
                , [{"Resource":["some_arn"], expected_key: expected_val, "Effect": "Allow"}]
                )

            assert_works("action", "iam:*", "Action", ["iam:*"])
            assert_works("Action", "iam:*", "Action", "iam:*")
            assert_works("notaction", "iam:*", "NotAction", ["iam:*"])
            assert_works("NotAction", "iam:*", "NotAction", "iam:*")

    describe "Filling out resource definition":
        before_each:
            self.role = Role(self.name, self.definition, self.amazon)

        it "yields strings as is":
            self.assertEqual(list(self.role.fill_out_resources("blah")), ["blah"])
            self.assertEqual(list(self.role.fill_out_resources(["blah"])), ["blah"])
            self.assertEqual(list(self.role.fill_out_resources(["blah", "other"])), ["blah", "other"])

        it "expands dictionaries":
            res1, eres1 = {1:2}, mock.Mock(name="eres1")
            res2, eres2, eres2b = {3:4}, mock.Mock(name="eres2"), mock.Mock(name="eres2b")

            fake_expand_resource = mock.Mock(name="expand_resource")
            fake_expand_resource.side_effect = lambda res: {str(res1):[eres1], str(res2):[eres2, eres2b]}[str(res)]

            with mock.patch.object(self.role, "expand_resource", fake_expand_resource):
                self.assertEqual(list(self.role.fill_out_resources(res1)), [eres1])
                self.assertEqual(list(self.role.fill_out_resources([res1])), [eres1])
                self.assertEqual(list(self.role.fill_out_resources([res1, res2])), [eres1, eres2, eres2b])
                self.assertEqual(list(self.role.fill_out_resources([res1, "blah", res2])), [eres1, "blah", eres2, eres2b])

        it "complains if resource is not a string or dictionary":
            for resource in (0, 1, None, True, False, [[1]], lambda: 1, mock.Mock(name="mock")):
                with self.assertRaisesRegexp(BadPolicy, "Resource should be a string or a dictionary.+"):
                    list(self.role.fill_out_resources(resource))

    describe "Expanding a resource":
        before_each:
            self.role = Role(self.name, self.definition, self.amazon)

        it "transforms using iam_arns_from_specification if iam in the resource":
            arn1 = mock.Mock(name="arn1")
            arn2 = mock.Mock(name="arn2")
            arn3 = mock.Mock(name="arn3")
            resource = mock.MagicMock(name="resource")
            resource.__contains__.side_effect = lambda key: key == "iam"

            fake_iam_arns_from_specification = mock.Mock(name="iam_arns_from_specification")
            fake_iam_arns_from_specification.return_value = [arn1, arn2, arn3]

            with mock.patch.object(self.role, "iam_arns_from_specification", fake_iam_arns_from_specification):
                self.assertEqual(list(self.role.expand_resource(resource)), [arn1, arn2, arn3])
            fake_iam_arns_from_specification.assert_called_once_with(resource)

        it "uses s3 as bucket and key":
            self.assertEqual(list(self.role.expand_resource({"s3": "bucket/key"})), ["arn:aws:s3:::bucket/key"])
            self.assertEqual(list(self.role.expand_resource({"s3": ["bucket1/key", "bucket2/key"]})), ["arn:aws:s3:::bucket1/key", "arn:aws:s3:::bucket2/key"])

        it "sets resources as bucket and bucket/* if / not in bucket_key":
            self.assertEqual(list(self.role.expand_resource({"s3": "bucket"})), ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"])

        it "complains if neither s3 or iam in the resource":
            resource = mock.MagicMock(name="resource")
            resource.__contains__.side_effect = lambda key: False
            with self.assertRaisesRegexp(BadPolicy, "Unknown resource type"):
                list(self.role.expand_resource(resource))
            self.assertEqual(resource.__contains__.mock_calls, [mock.call("iam"), mock.call("s3")])

    describe "Getting iam arn from a specification":
        before_each:
            self.role = Role(self.name, self.definition, self.amazon)

        it "uses account_id from the amazon object and name from the role when __self__ is specified":
            name = uuid.uuid1()
            account_id = uuid.uuid1()

            self.role.name = name
            self.role.amazon.account_id = account_id

            expected = "arn:aws:iam::{0}:role/{1}".format(account_id, name)
            self.assertEqual(list(self.role.iam_arns_from_specification({"iam": "__self__"})), [expected])

        it "doesn't use specified account if __self__ is specified":
            name = uuid.uuid1()
            account_id = uuid.uuid1()
            unused_account = uuid.uuid1()
            accounts = {account_id: account_id, unused_account:unused_account}

            self.role.name = name
            self.role.amazon.accounts = accounts
            self.role.amazon.account_id = account_id

            expected = "arn:aws:iam::{0}:role/{1}".format(account_id, name)
            self.assertEqual(list(self.role.iam_arns_from_specification({"iam": "__self__", "account": unused_account})), [expected])

        it "complains if provided account is unknown":
            self.role.amazon.accounts = {}
            with self.assertRaisesRegexp(BadPolicy, "Unknown account specified.+"):
                list(self.role.iam_arns_from_specification({"account": "unknown"}))

        it "uses provided account and name from the value":
            self.role.amazon.accounts = {"dev":9001, "prod":9002}
            assert_good = lambda policy, expected: self.assertEqual(list(self.role.iam_arns_from_specification(policy)), expected)
            assert_good({"iam":"joe", "account":"dev"}, ["arn:aws:iam::9001:joe"])
            assert_good({"iam":["joe"], "account":"dev"}, ["arn:aws:iam::9001:joe"])
            assert_good({"iam":["joe", "user/fred"], "account":"dev"}, ["arn:aws:iam::9001:joe", "arn:aws:iam::9001:user/fred"])

        it "uses name from value and current account if no account is specified":
            self.role.amazon.account_id = 9003
            assert_good = lambda policy, expected: self.assertEqual(list(self.role.iam_arns_from_specification(policy)), expected)
            assert_good({"iam":"steve"}, ["arn:aws:iam::9003:steve"])

        it "yields the arns if supplied as strings":
            self.role.amazon.account_id = 9004
            assert_good = lambda policy, expected: self.assertEqual(list(self.role.iam_arns_from_specification(policy)), expected)
            assert_good(["arn:aws:iam::9004:yeap", "arn:aws:iam::9005:tree"], ["arn:aws:iam::9004:yeap", "arn:aws:iam::9005:tree"])
            assert_good("arn:aws:iam::9004:yeap", ["arn:aws:iam::9004:yeap"])

    describe "Making a trust document":
        before_each:
            self.role = Role(self.name, self.definition, self.amazon)

        it "returns nothing if no trust or distrust":
            self.assertIs(self.role.make_trust_document([], []), None)
            self.assertIs(self.role.make_trust_document([], None), None)
            self.assertIs(self.role.make_trust_document(None, []), None)
            self.assertIs(self.role.make_trust_document(None, None), None)

        it "Makes a document with the combined trust and distrust":
            result = mock.Mock(name="result")
            fake_make_document = mock.Mock(name="make_document")
            fake_make_document.return_value = result

            trust = mock.Mock(name="trust")
            distrust = mock.Mock(name="distrust")

            with mock.patch.object(self.role, "make_document", fake_make_document):
                self.assertIs(self.role.make_trust_document([trust], [distrust]), result)
                fake_make_document.assert_called_once_with([trust, distrust])

                fake_make_document.reset_mock()
                self.assertIs(self.role.make_trust_document([trust], None), result)
                fake_make_document.assert_called_once_with([trust])

                fake_make_document.reset_mock()
                self.assertIs(self.role.make_trust_document(None, [distrust]), result)
                fake_make_document.assert_called_once_with([distrust])

    describe "Making a permission document":
        before_each:
            self.role = Role(self.name, self.definition, self.amazon)

        it "returns none if no permissions":
            self.assertIs(self.role.make_permission_document([]), None)
            self.assertIs(self.role.make_permission_document(None), None)

        it "makes a document from it otherwise":
            result = mock.Mock(name="result")
            permissions = mock.Mock(name="permissions")
            fake_make_document = mock.Mock(name="make_document")
            fake_make_document.return_value = result

            with mock.patch.object(self.role, "make_document", fake_make_document):
                self.assertIs(self.role.make_permission_document(permissions), result)
            fake_make_document.assert_called_once_with(permissions)

    describe "making a document":
        before_each:
            self.role = Role(self.name, self.definition, self.amazon)

        it "complains if given something that isn't a list":
            for statements in (0, 1, None, True, False, {}, {1:2}, lambda: 1, mock.Mock(name="blah"), "blah"):
                with self.assertRaisesRegexp(Exception, "Statements should be a list!.+"):
                    self.role.make_document(statements)

        it "wraps the document with a Version and Statement and json dumps it":
            statements = [mock.Mock(name="statements")]
            dumped = mock.Mock(name="dumped")

            fake_dumps = mock.Mock(name="dumps")
            fake_dumps.return_value = dumped

            with mock.patch("json.dumps", fake_dumps):
                self.assertIs(self.role.make_document(statements), dumped)
            fake_dumps.assert_called_once_with({"Version": "2012-10-17", "Statement":statements}, indent=2)

        it "raises invalid json as an InvalidDocument exception":
            with self.assertRaisesRegexp(InvalidDocument, "Document wasn't valid json.+"):
                self.role.make_document([set([1, 2])])

