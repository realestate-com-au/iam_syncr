# coding: spec

from iam_syncr.errors import BadRole, BadPolicy, InvalidDocument
from iam_syncr.amazon.roles import AmazonRoles
from iam_syncr.roles import RoleRemoval, Role
from iam_syncr.amazon.base import Amazon

from noseOfYeti.tokeniser.support import noy_sup_setUp
from textwrap import dedent
import uuid
import six

from tests.helpers import TestCase

if six.PY2:
    import mock
else:
    from unittest import mock

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
                with self.fuzzyAssertRaisesError(BadRole, "Told to remove a role, but not specified as a string"):
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
                  str(princ1):[str(tprinc1)], str(princ2):[str(tprinc2)], str(princ3):[str(tprinc3)]
                , str(princ4):[str(tprinc4)], str(princ5):[str(tprinc5)], str(princ6):[str(tprinc6)]
                }

            allow_to_assume_me = [str(princ1), str(princ2), str(princ3)]
            disallow_to_assume_me = [str(princ4), str(princ5), str(princ6)]
            fake_expand_trust_statement = mock.Mock(name="expand_trust_statement")
            fake_expand_trust_statement.side_effect = lambda princ, allow=False: transformed[str(princ)]

            # With lists of principals
            role = Role(self.name, {"allow_to_assume_me": allow_to_assume_me, "disallow_to_assume_me": disallow_to_assume_me}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role.statements, "expand_trust_statement", fake_expand_trust_statement):
                role.setup()
            self.assertSortedEqual(role.trust, [str(tprinc1), str(tprinc2), str(tprinc3)])
            self.assertSortedEqual(role.distrust, [str(tprinc4), str(tprinc6), str(tprinc5)])

            # And not giving lists
            role = Role(self.name, {"allow_to_assume_me": princ1, "disallow_to_assume_me": princ2}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role.statements, "expand_trust_statement", fake_expand_trust_statement):
                role.setup()
            self.assertSortedEqual(role.trust, [str(tprinc1)])
            self.assertSortedEqual(role.distrust, [str(tprinc2)])

            # And with only allow
            role = Role(self.name, {"allow_to_assume_me": str(princ1)}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role.statements, "expand_trust_statement", fake_expand_trust_statement):
                role.setup()
            self.assertSortedEqual(role.trust, [str(tprinc1)])
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
            with mock.patch.object(role.statements, "make_permission_statements", fake_make_permission_statements):
                role.setup()
            self.assertEqual(role.permission, [(tpol3, None), (tpol1, True), (tpol1b, True), (tpol2, True), (tpol4, False), (tpol5, False), (tpol6, False)])

            # And not giving lists
            role = Role(self.name, {"allow_permission": pol1, "deny_permission": pol2, "permission": pol3}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role.statements, "make_permission_statements", fake_make_permission_statements):
                role.setup()
            self.assertEqual(role.permission, [(tpol3, None), (tpol1, True), (tpol1b, True), (tpol2, False)])

            # And with only allow
            role = Role(self.name, {"allow_permission": pol1}, self.amazon)
            self.assertEqual(role.trust, [])
            self.assertEqual(role.distrust, [])
            with mock.patch.object(role.statements, "make_permission_statements", fake_make_permission_statements):
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

            with mock.patch.object(self.role.statements, "make_document", fake_make_document):
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

            with mock.patch.object(self.role.statements, "make_document", fake_make_document):
                self.assertIs(self.role.make_permission_document(permissions), result)
            fake_make_document.assert_called_once_with(permissions)

