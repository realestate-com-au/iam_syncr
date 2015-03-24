# coding: spec

from iam_syncr.errors import SyncrError, BadConfiguration, InvalidConfiguration, NoConfiguration
from iam_syncr import executor

from tests.helpers import a_file, a_directory

from argparse import ArgumentTypeError
import yaml
import six
import os

from tests.helpers import TestCase

if six.PY2:
    import mock
else:
    from unittest import mock

describe TestCase, "cli arguments":
    describe "Readable folder":
        it "complains if the path doesn't exist":
            with a_directory(removed=True) as directory:
                with self.fuzzyAssertRaisesError(ArgumentTypeError, "{0} doesn't exist".format(directory)):
                    executor.argparse_readable_folder(directory)

        it "complains if it's not a directory":
            with a_file() as filename:
                with self.fuzzyAssertRaisesError(ArgumentTypeError, "{0} exists but isn't a folder".format(filename)):
                    executor.argparse_readable_folder(filename)

        it "complains if it's not readable":
            with a_directory() as directory:
                os.chmod(directory, 0o344)
                try:
                    with self.fuzzyAssertRaisesError(ArgumentTypeError, "{0} exists and is a folder but isn't readable".format(directory)):
                        executor.argparse_readable_folder(directory)
                finally:
                    os.chmod(directory, 0o644)

        it "is fine with it if it's just a directory":
            with a_directory() as directory:
                self.assertEqual(executor.argparse_readable_folder(directory), directory)

describe TestCase, "Finding accounts":
    it "complains if the accounts doesn't exist":
        with self.fuzzyAssertRaisesError(SyncrError, "Could not find an accounts\.yaml"):
            with a_file(removed=True) as filename:
                executor.accounts_from(filename)

    it "complains if the accounts isn't readable":
        with self.fuzzyAssertRaisesError(SyncrError, "Could not read the accounts\.yaml"):
            with a_file() as filename:
                os.chmod(filename, 0o344)
                executor.accounts_from(filename)

    it "Complains if it can't read the yaml":
        with self.fuzzyAssertRaisesError(SyncrError, "Failed to parse the accounts yaml file"):
            with a_file("{blah.things: 2{}}") as filename:
                executor.accounts_from(filename)

    it "Returns the accounts as a dictionary":
        accounts = {"dev":12, "prod":34, 12:12, 34:34}

        with a_file(yaml.dump(accounts)) as filename:
            result = executor.accounts_from(filename)

        self.assertEqual(result, accounts)

    it "Adds account_id to account_id if not already there":
        accounts = {"dev":12, "prod":34}

        with a_file(yaml.dump(accounts)) as filename:
            result = executor.accounts_from(filename)

        expected = {"dev":12, "prod":34, 12:12, 34:34}
        self.assertEqual(result, expected)

describe TestCase, "Making Amazon object":
    it "defaults to finding accounts yaml from parent of folder":
        fakeAmazon = mock.Mock(name="fakeAmazon")
        amazon_instance = mock.Mock(name="amazon_instance")
        fakeAmazon.return_value = amazon_instance

        accounts = {"dev": 12}
        fake_accounts_from = mock.Mock(name="accounts_from")
        fake_accounts_from.return_value = accounts

        with mock.patch("iam_syncr.executor.accounts_from", fake_accounts_from):
            with mock.patch("iam_syncr.executor.Amazon", fakeAmazon):
                with a_directory() as directory:
                    accounts_location = os.path.join(directory, "accounts.yaml")
                    folder = os.path.join(directory, "dev")
                    instance = executor.make_amazon(folder)

        self.assertIs(instance, amazon_instance)
        fakeAmazon.assert_called_once_with(12, "dev", accounts, dry_run=False)
        amazon_instance.setup.assert_called_once()

        # Mock probably makes it easier to do this check, I'll come back to it another day
        self.assertEqual(len(fake_accounts_from.mock_calls), 1)
        _, args, _ = fake_accounts_from.mock_calls[0]
        self.assertEqual(len(args), 1)
        self.assertEqual(os.path.normpath(args[0]), accounts_location)

    it "uses provided accounts_location":
        fakeAmazon = mock.Mock(name="fakeAmazon")
        amazon_instance = mock.Mock(name="amazon_instance")
        fakeAmazon.return_value = amazon_instance

        accounts_location = mock.Mock(name="accounts_location")

        accounts = {"dev": 12, "staging": 32}
        fake_accounts_from = mock.Mock(name="accounts_from")
        fake_accounts_from.return_value = accounts

        with mock.patch("iam_syncr.executor.accounts_from", fake_accounts_from):
            with mock.patch("iam_syncr.executor.Amazon", fakeAmazon):
                with a_directory() as directory:
                    folder = os.path.join(directory, "staging")
                    instance = executor.make_amazon(folder, accounts_location)

        self.assertIs(instance, amazon_instance)
        fakeAmazon.assert_called_once_with(32, "staging", accounts, dry_run=False)
        amazon_instance.setup.assert_called_once()
        fake_accounts_from.assert_called_once_with(accounts_location)

    it "complains if can't find the account name in the accounts":
        accounts = {}
        accounts_location = mock.Mock(name="accounts_location")
        fake_accounts_from = mock.Mock(name="accounts_from")
        fake_accounts_from.return_value = accounts

        with self.fuzzyAssertRaisesError(SyncrError, "Please add this account to accounts\.yaml", account_name="prod"):
            with mock.patch("iam_syncr.executor.accounts_from", fake_accounts_from):
                with a_directory() as directory:
                    folder = os.path.join(directory, "prod")
                    executor.make_amazon(folder, accounts_location)

describe TestCase, "Doing the sync":
    it "Parses configurations, creates sync, adds configurations and does the sync":
        fake_found = mock.Mock(name="found")
        fake_amazon = mock.Mock(name="amazon")
        fake_combined = mock.Mock(name="combined")
        fake_only_consider = [mock.Mock(name="only_consider")]
        fake_parse_configurations = mock.Mock(name="parse_configurations")

        fakeSync = mock.Mock(name="Sync")
        sync_instance = mock.Mock(name="sync_instance")
        sync_instance.types = {fake_only_consider[0]: True}
        fakeSync.return_value = sync_instance

        called = []
        sync_instance.register_default_types.side_effect = lambda: called.append(1)
        sync_instance.add.side_effect = lambda conf, location, only_consider: called.append((conf, location, only_consider))
        def combine():
            called.append(2)
            return fake_combined
        sync_instance.combine_configurations.side_effect = combine
        sync_instance.sync.side_effect = lambda comb: called.append(comb)

        conf1, loc1 = mock.Mock(name="conf1"), "location1"
        conf2, loc2 = mock.Mock(name="conf2"), "location2"
        parsed = {loc1: conf1, loc2: conf2}

        fake_parse_configurations.return_value = parsed

        with mock.patch.multiple("iam_syncr.executor", parse_configurations=fake_parse_configurations, Sync=fakeSync):
            executor.do_sync(fake_amazon, fake_found, only_consider=fake_only_consider)

        self.assertEqual(called
            , [ 1
              , (conf1, loc1, fake_only_consider)
              , (conf2, loc2, fake_only_consider)
              , 2
              , fake_combined
              ]
            )

    it "complains if the sync doesn't have a type we want to consider":
        fake_found = mock.Mock(name="found")
        fake_amazon = mock.Mock(name="amazon")
        fake_parse_configurations = mock.Mock(name="parse_configurations")
        fake_parse_configurations.return_value = {"somewhere": {}}

        with self.fuzzyAssertRaisesError(SyncrError, "Told to sync unknown types", unknown_types=['blah', 'stuff']):
            with mock.patch("iam_syncr.executor.parse_configurations", fake_parse_configurations):
                executor.do_sync(fake_amazon, fake_found, ["blah", "stuff"])

describe TestCase, "Parsing configuration":
    it "raises BadConfiguration with parse_errors as a list of the errors that were encountered":
        errors = None
        with a_directory() as directory:
            conf1 = os.path.join(directory, "conf1")
            conf2 = os.path.join(directory, "conf2")
            conf3 = os.path.join(directory, "conf3")
            with open(conf1, 'w') as fle:
                fle.write("{thing.blah: d][}")
            with open(conf2, 'w') as fle:
                fle.write("{hello: there}")
            with open(conf3, 'w') as fle:
                fle.write("}{]]]")

            try:
                executor.parse_configurations([conf1, conf2, conf3])
                assert False, "That should have failed...."
            except BadConfiguration as error:
                errors = error.kwargs["parse_errors"]

        if not errors:
            assert False, "Ummm, errors shouldn't be None here"

        self.assertEqual(set(errors.keys()), set([conf1, conf3]))
        for val in errors.values():
            assert isinstance(val, InvalidConfiguration)
            self.assertEqual(val.message, "Couldn't parse the yaml")

describe TestCase, "Finding the configuration":
    it "complains if it can't find any configuration":
        with self.fuzzyAssertRaisesError(NoConfiguration):
            with a_directory() as directory:
                executor.find_configurations(directory, "*.yaml")

    it "finds all the files that match the glob":
        with a_directory() as directory:
            child = os.path.join(directory, "child")
            grandchild = os.path.join(child, "grandchild")
            greatgrandchild = os.path.join(grandchild, "greatgrandchild")

            child2 = os.path.join(directory, "child2")
            grandchild2 = os.path.join(child2, "grandchild2")

            os.makedirs(grandchild)
            os.makedirs(grandchild2)
            os.makedirs(greatgrandchild)

            conf1 = os.path.join(child, "conf1.yaml")
            conf2 = os.path.join(child, "conf2.yml")
            conf3 = os.path.join(grandchild, "conf3.yaml")
            conf4 = os.path.join(child2, "conf4.yaml")
            conf5 = os.path.join(grandchild2, "conf5.yaml")
            conf6 = os.path.join(grandchild2, "conf6.yaml")
            conf7 = os.path.join(child2, "conf7.blah")
            conf8 = os.path.join(greatgrandchild, "conf8.yaml")

            for conf in [conf1, conf2, conf3, conf4, conf5, conf6, conf7, conf8]:
                with open(conf, 'w') as fle:
                    fle.write("{}")

            def assert_configs_for(glb, expected):
                result = set(executor.find_configurations(directory, glb))
                expected = set(expected)

                if result != expected:
                    print('Got ============>')
                    print(sorted(result))
                    print('Expected ---------->')
                    print(sorted(expected))
                self.assertEqual(result, expected)

            assert_configs_for("*.yaml", [conf1, conf3, conf4, conf5, conf6, conf8])
            assert_configs_for("*.blah", [conf7])
            assert_configs_for("child/**", [conf1, conf2, conf3, conf8])
            assert_configs_for("*/grand*/*", [conf3, conf5, conf6, conf8])

