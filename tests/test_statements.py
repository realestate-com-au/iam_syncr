# coding: spec

from iam_syncr.errors import BadRole, BadPolicy, InvalidDocument
from iam_syncr.amazon.roles import AmazonRoles
from iam_syncr.statements import Statements
from iam_syncr.amazon.base import Amazon

from noseOfYeti.tokeniser.support import noy_sup_setUp
from textwrap import dedent
import uuid
import mock

from tests.helpers import TestCase

describe TestCase, "Statements":
    before_each:
        self.name = str(uuid.uuid1())
        self.account_id = str(uuid.uuid1())
        self.accounts = {"prod": self.account_id, self.account_id: self.account_id}
        self.statements = Statements(self.name, 'role', self.account_id, self.accounts)

    describe "Expanding trust statements":
        def statements_from(self, statement, allow=False):
            """Make a Role and use it to normalise a principal"""
            return list(self.statements.expand_trust_statement(statement, allow=allow))

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

            with mock.patch.object(self.statements, "iam_arns_from_specification", iam_arns_from_specification):
                self.assertEqual(self.statements_from({"federated": iam_specs}, allow=True), [{"Action": "sts:AssumeRoleWithSAML", "Effect": "Allow", "Sid": "", "Principal": {"Federated": transformed_specs}}])

            iam_arns_from_specification.assert_called_once_with(iam_specs)

        it "sets AWS to expanded iam_roles":
            iam_specs = mock.Mock(name="iam_specs")
            transformed_specs = mock.Mock(name="transformed_specs")
            iam_arns_from_specification = mock.Mock(name="iam_arns_from_specification")
            iam_arns_from_specification.return_value = [transformed_specs]

            with mock.patch.object(self.statements, "iam_arns_from_specification", iam_arns_from_specification):
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
            make_statements = lambda : sorted(list(self.statements.make_permission_statements(policy, allow=allow)))
            if not patches:
                return make_statements()
            else:
                with mock.patch.multiple(self.statements, **patches):
                    return make_statements()

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
                self.assertEqual(self.statements_from(policy, allow=True), [{"Effect": "Allow", "Resource": "resource", dest: "Stuff"}])
                self.assertEqual(self.statements_from(policy, allow=False), [{"Effect": "Deny", "Resource": "resource", dest: "Stuff"}])

                policy = {"Resource": "resource", key: ["Stuff"]}
                self.assertEqual(self.statements_from(policy, allow=True), [{"Effect": "Allow", "Resource": "resource", dest: "Stuff"}])
                self.assertEqual(self.statements_from(policy, allow=False), [{"Effect": "Deny", "Resource": "resource", dest: "Stuff"}])

                policy = {"Resource": "resource", key: ["Stuff", "otHer:*"]}
                self.assertEqual(self.statements_from(policy, allow=True), [{"Effect": "Allow", "Resource": "resource", dest: sorted(["Stuff", "otHer:*"])}])
                self.assertEqual(self.statements_from(policy, allow=False), [{"Effect": "Deny", "Resource": "resource", dest: sorted(["Stuff", "otHer:*"])}])

        it "sets Resource and NotResource from resource and notresource":
            res1, tres1 = mock.Mock(name="res1"), mock.Mock(name="tres1")
            res2, tres2 = mock.Mock(name="res2"), mock.Mock(name="tres2")
            res3, tres3, tres4 = mock.Mock(name="res3"), mock.Mock(name="tres3"), mock.Mock(name="tres4")

            fake_fill_out_resources = mock.Mock(name="fill_out_resources")
            fake_fill_out_resources.side_effect = lambda res: {res1:[tres1], res2:[tres2], res3:[tres3, tres4]}[res]
            patches = {"fill_out_resources": fake_fill_out_resources}

            for key, dest in (("resource", "Resource"), ("notresource", "NotResource")):
                policy = {"Action": "action", key: res1}
                self.assertEqual(self.statements_from(policy, allow=True, patches=patches), [{"Effect": "Allow", "Action": "action", dest: tres1}])
                self.assertEqual(self.statements_from(policy, allow=False, patches=patches), [{"Effect": "Deny", "Action": "action", dest: tres1}])

                policy = {"Action": "action", key: [res1]}
                self.assertEqual(self.statements_from(policy, allow=True, patches=patches), [{"Effect": "Allow", "Action": "action", dest: tres1}])
                self.assertEqual(self.statements_from(policy, allow=False, patches=patches), [{"Effect": "Deny", "Action": "action", dest: tres1}])

                policy = {"Action": "action", key: [res2, res3]}
                self.assertEqual(self.statements_from(policy, allow=True, patches=patches), [{"Effect": "Allow", "Action": "action", dest: sorted([tres2, tres3, tres4])}])
                self.assertEqual(self.statements_from(policy, allow=False, patches=patches), [{"Effect": "Deny", "Action": "action", dest: sorted([tres2, tres3, tres4])}])

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
                , [{"Resource":"some_arn", expected_key: expected_val, "Effect": "Allow"}]
                )

            assert_works("action", "iam:*", "Action", "iam:*")
            assert_works("Action", "iam:*", "Action", "iam:*")
            assert_works("notaction", "iam:*", "NotAction", "iam:*")
            assert_works("NotAction", "iam:*", "NotAction", "iam:*")

    describe "Filling out resource definition":
        it "yields strings as is":
            self.assertEqual(list(self.statements.fill_out_resources("blah")), ["blah"])
            self.assertEqual(list(self.statements.fill_out_resources(["blah"])), ["blah"])
            self.assertEqual(list(self.statements.fill_out_resources(["blah", "other"])), ["blah", "other"])

        it "expands dictionaries":
            res1, eres1 = {1:2}, mock.Mock(name="eres1")
            res2, eres2, eres2b = {3:4}, mock.Mock(name="eres2"), mock.Mock(name="eres2b")

            fake_expand_resource = mock.Mock(name="expand_resource")
            fake_expand_resource.side_effect = lambda res: {str(res1):[eres1], str(res2):[eres2, eres2b]}[str(res)]

            with mock.patch.object(self.statements, "expand_resource", fake_expand_resource):
                self.assertEqual(list(self.statements.fill_out_resources(res1)), [eres1])
                self.assertEqual(list(self.statements.fill_out_resources([res1])), [eres1])
                self.assertEqual(list(self.statements.fill_out_resources([res1, res2])), [eres1, eres2, eres2b])
                self.assertEqual(list(self.statements.fill_out_resources([res1, "blah", res2])), [eres1, "blah", eres2, eres2b])

        it "complains if resource is not a string or dictionary":
            for resource in (0, 1, None, True, False, [[1]], lambda: 1, mock.Mock(name="mock")):
                with self.assertRaisesRegexp(BadPolicy, "Resource should be a string or a dictionary.+"):
                    list(self.statements.fill_out_resources(resource))

    describe "Expanding a resource":
        it "transforms using iam_arns_from_specification if iam in the resource":
            arn1 = mock.Mock(name="arn1")
            arn2 = mock.Mock(name="arn2")
            arn3 = mock.Mock(name="arn3")
            resource = mock.MagicMock(name="resource")
            resource.__contains__.side_effect = lambda key: key == "iam"

            fake_iam_arns_from_specification = mock.Mock(name="iam_arns_from_specification")
            fake_iam_arns_from_specification.return_value = [arn1, arn2, arn3]

            with mock.patch.object(self.statements, "iam_arns_from_specification", fake_iam_arns_from_specification):
                self.assertEqual(list(self.statements.expand_resource(resource)), [arn1, arn2, arn3])
            fake_iam_arns_from_specification.assert_called_once_with(resource)

        it "uses s3 as bucket and key":
            self.assertEqual(list(self.statements.expand_resource({"s3": "bucket/key"})), ["arn:aws:s3:::bucket/key"])
            self.assertEqual(list(self.statements.expand_resource({"s3": ["bucket1/key", "bucket2/key"]})), ["arn:aws:s3:::bucket1/key", "arn:aws:s3:::bucket2/key"])

        it "uses current name as bucket if using __self__ with s3":
            self.statements.self_type = "bucket"
            self.assertEqual(list(self.statements.expand_resource({"s3": "__self__"})), ["arn:aws:s3:::{0}".format(self.name), "arn:aws:s3:::{0}/*".format(self.name)])

        it "sets resources as bucket and bucket/* if / not in bucket_key":
            self.assertEqual(list(self.statements.expand_resource({"s3": "bucket"})), ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"])

        it "complains if neither s3 or iam in the resource":
            resource = mock.MagicMock(name="resource")
            resource.__contains__.side_effect = lambda key: False
            with self.assertRaisesRegexp(BadPolicy, "Unknown resource type"):
                list(self.statements.expand_resource(resource))
            self.assertEqual(resource.__contains__.mock_calls, [mock.call("iam"), mock.call("s3")])

    describe "Getting iam arn from a specification":
        it "uses self.account_id when __self__ is specified":
            expected = "arn:aws:iam::{0}:role/{1}".format(self.account_id, self.name)
            self.assertEqual(list(self.statements.iam_arns_from_specification({"iam": "__self__"})), [expected])

        it "complains if self_type is bucket and __self__ is used":
            with self.assertRaisesRegexp(BadPolicy, "Bucket policy has no __self__ iam role.+"):
                self.statements.self_type = "bucket"
                list(self.statements.iam_arns_from_specification({"iam": "__self__"}))

        it "doesn't use specified account if __self__ is specified":
            unused_account = uuid.uuid1()
            self.accounts[unused_account] = unused_account

            expected = "arn:aws:iam::{0}:role/{1}".format(self.account_id, self.name)
            self.assertEqual(list(self.statements.iam_arns_from_specification({"iam": "__self__", "account": unused_account})), [expected])

        it "complains if provided account is unknown":
            self.statements.accounts = {}
            with self.assertRaisesRegexp(BadPolicy, "Unknown account specified.+"):
                list(self.statements.iam_arns_from_specification({"account": "unknown"}))

        it "uses provided account and name from the value":
            self.accounts["dev"] = 9001
            self.accounts["prod"] = 9002
            assert_good = lambda policy, expected: self.assertEqual(list(self.statements.iam_arns_from_specification(policy)), expected)
            assert_good({"iam":"joe", "account":"dev"}, ["arn:aws:iam::9001:joe"])
            assert_good({"iam":["joe"], "account":"dev"}, ["arn:aws:iam::9001:joe"])
            assert_good({"iam":["joe", "user/fred"], "account":"dev"}, ["arn:aws:iam::9001:joe", "arn:aws:iam::9001:user/fred"])

        it "uses name from value and current account if no account is specified":
            assert_good = lambda policy, expected: self.assertEqual(list(self.statements.iam_arns_from_specification(policy)), expected)
            assert_good({"iam":"steve"}, ["arn:aws:iam::{0}:steve".format(self.account_id)])

        it "yields the arns if supplied as strings":
            assert_good = lambda policy, expected: self.assertEqual(list(self.statements.iam_arns_from_specification(policy)), expected)
            assert_good(["arn:aws:iam::9004:yeap", "arn:aws:iam::9005:tree"], ["arn:aws:iam::9004:yeap", "arn:aws:iam::9005:tree"])
            assert_good("arn:aws:iam::9004:yeap", ["arn:aws:iam::9004:yeap"])

        it "yields from multiple accounts and users":
            self.accounts["dev"] = 9003
            self.accounts["prod"] = 9004
            assert_good = lambda policy, expected: self.assertEqual(list(self.statements.iam_arns_from_specification(policy)), expected)
            assert_good(
                  {"iam":"role", "account":["dev", "prod"], "users":["bob", "jane"]}
                , ["arn:aws:iam::9003:role/bob", "arn:aws:iam::9003:role/jane", "arn:aws:iam::9004:role/bob", "arn:aws:iam::9004:role/jane"]
                )

    describe "making a document":
        it "complains if given something that isn't a list":
            for statements in (0, 1, None, True, False, {}, {1:2}, lambda: 1, mock.Mock(name="blah"), "blah"):
                with self.assertRaisesRegexp(Exception, "Statements should be a list!.+"):
                    self.statements.make_document(statements)

        it "wraps the document with a Version and Statement and json dumps it":
            statements = [mock.Mock(name="statements")]
            dumped = mock.Mock(name="dumped")

            fake_dumps = mock.Mock(name="dumps")
            fake_dumps.return_value = dumped

            with mock.patch("json.dumps", fake_dumps):
                self.assertIs(self.statements.make_document(statements), dumped)
            fake_dumps.assert_called_once_with({"Version": "2012-10-17", "Statement":statements}, indent=2)

        it "raises invalid json as an InvalidDocument exception":
            with self.assertRaisesRegexp(InvalidDocument, "Document wasn't valid json.+"):
                self.statements.make_document([set([1, 2])])

