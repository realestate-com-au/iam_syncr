# coding: spec

from iam_syncr.errors import SyncrError, BadConfiguration, DuplicateItem, ConflictingConfiguration, InvalidConfiguration
from iam_syncr.amazon import Amazon
from iam_syncr.syncer import Sync

from noseOfYeti.tokeniser.support import noy_sup_setUp
import mock

from tests.helpers import TestCase

describe TestCase, "Sync":
    before_each:
        self.amazon = mock.create_autospec(spec=Amazon, instance=True, spec_set=True)
        self.sync = Sync(self.amazon)

    it "takes in an amazon object and inits types and configurations":
        amazon = mock.Mock(name="amazon")
        sync = Sync(amazon)

        self.assertIs(sync.amazon, amazon)
        self.assertEqual(sync.types, {})
        self.assertEqual(sync.configurations, {})

        # It's a default dict of list
        self.assertEqual(sync.configurations["roles"], [])

    describe "Syncing":
        it "creates, setups, and resolves things in combined that are in types":
            roles = mock.Mock(name="roles")
            other = mock.Mock(name="other")
            things = mock.Mock(name="things")
            combined = {"roles": roles, "other": other}
            self.sync.register_type("roles", dict, mock.Mock(name="kls"))

            self.assertEqual(self.sync.types.keys(), ["roles"])

            fake_create_things = mock.Mock(name="create_things")
            fake_create_things.return_value = things
            fake_setup_and_resolve = mock.Mock(name="setup_and_resolve")

            with mock.patch.multiple(self.sync, create_things=fake_create_things, setup_and_resolve=fake_setup_and_resolve):
                self.sync.sync(combined)

            fake_create_things.assert_called_once_with(roles, "roles")
            fake_setup_and_resolve.called_once_with(things)

    describe "Registering a type":
        it "just adds it to types":
            kls = mock.Mock(name="kls")
            self.assertEqual(self.sync.types, {})
            self.sync.register_type("roles", dict, kls)
            self.assertEqual(self.sync.types, {"roles": (dict, None, kls)})

        it "puts key_conflicts_with in a list if not already in one":
            kls = mock.Mock(name="kls")
            self.assertEqual(self.sync.types, {})
            self.sync.register_type("roles", dict, kls, key_conflicts_with="blah")
            self.assertEqual(self.sync.types, {"roles": (dict, ["blah"], kls)})

        it "adds key_conflicts_with as is if a list":
            kls = mock.Mock(name="kls")
            self.assertEqual(self.sync.types, {})
            self.sync.register_type("roles", dict, kls, key_conflicts_with=["other"])
            self.assertEqual(self.sync.types, {"roles": (dict, ["other"], kls)})

    describe "Creating things":
        it "instantiates the kls with just thing if a list":
            called = []
            created = {
                  "one": mock.Mock(name="one")
                , "two": mock.Mock(name="two")
                , "three": mock.Mock(name="three")
                }

            kls = mock.Mock(name="kls")
            def instantiate(thing, amazon):
                called.append((thing, amazon))
                return created[thing]
            kls.side_effect = instantiate

            self.sync.register_type("blah", list, kls)
            things = ["one", "two", "three"]

            self.assertEqual(self.sync.create_things(things, "blah"), [created["one"], created["two"], created["three"]])
            self.assertEqual(called, [("one", self.amazon), ("two", self.amazon), ("three", self.amazon)])

        it "instantiates the kls with thing and value if a dict":
            called = []
            created = {
                  "one": mock.Mock(name="one")
                , "two": mock.Mock(name="two")
                , "three": mock.Mock(name="three")
                }

            kls = mock.Mock(name="kls")
            def instantiate(thing, val, amazon):
                called.append((thing, val, amazon))
                return created[thing]
            kls.side_effect = instantiate

            self.sync.register_type("blah", dict, kls)
            things = {"one": "one_val", "two": "two_val", "three": "three_val"}

            self.assertEqual(set(self.sync.create_things(things, "blah")), set([created["one"], created["two"], created["three"]]))
            self.assertEqual(set(called), set([("one", "one_val", self.amazon), ("two", "two_val", self.amazon), ("three", "three_val", self.amazon)]))

    describe "setup and resolve":
        it "calls setup on all the things and then calls resolve on all the things":
            called = []
            things = []
            def make_mock(name):
                nxt = mock.Mock(name=name)
                nxt.setup.side_effect = lambda: called.append(("setup", name))
                nxt.resolve.side_effect = lambda: called.append(("resolve", name))
                return nxt

            for thing in ["thing1", "thing2", "thing3"]:
                things.append(make_mock(thing))

            self.sync.setup_and_resolve(things)
            self.assertEqual(called
                , [ ("setup", "thing1")
                  , ("setup", "thing2")
                  , ("setup", "thing3")
                  , ("resolve", "thing1")
                  , ("resolve", "thing2")
                  , ("resolve", "thing3")
                  ]
                )

    describe "Adding configuration":
        it "complains if types is empty":
            self.assertEqual(self.sync.types, {})
            with self.assertRaisesRegexp(SyncrError, "Syncr doesn't know about anything, try syncr.register_default_types\(\) first"):
                self.sync.add(mock.Mock(name="configuration"), "somewhere")

        it "complains if the configuration isn't a dictionary":
            self.sync.register_default_types()
            for conf in (0, 1, True, False, None, [], [1], lambda: None, mock.Mock(name="conf")):
                with self.assertRaisesRegexp(SyncrError, "Configuration needs to be a dict.+"):
                    self.sync.add(conf, "somewhere")

        it "Adds to self.configuration what is found in the configuration for each known type":
            location = mock.Mock(name="location")
            blah_conf = mock.Mock(name="blah_conf")
            other_conf = mock.Mock(name="other_conf")
            stuff_conf = mock.Mock(name="stuff_conf")

            self.sync.register_type("blah", dict, mock.Mock(name="kls"))
            self.sync.register_type("other", dict, mock.Mock(name="kls"))

            configuration = {"blah": blah_conf, "other": other_conf, "stuff": stuff_conf}
            self.assertEqual(self.sync.configurations, {})

            self.sync.add(configuration, location)
            self.assertEqual(self.sync.configurations, {"blah": [(location, blah_conf)], "other": [(location, other_conf)]})

        it "only adds the configurations in only_consider if specified":
            location = mock.Mock(name="location")
            blah_conf = mock.Mock(name="blah_conf")
            other_conf = mock.Mock(name="other_conf")
            stuff_conf = mock.Mock(name="stuff_conf")

            self.sync.register_type("blah", dict, mock.Mock(name="kls"))
            self.sync.register_type("other", dict, mock.Mock(name="kls"))

            configuration = {"blah": blah_conf, "other": other_conf, "stuff": stuff_conf}
            self.assertEqual(self.sync.configurations, {})

            self.sync.add(configuration, location, only_consider=["blah"])
            self.assertEqual(self.sync.configurations, {"blah": [(location, blah_conf)]})

    describe "Combining configurations":
        it "raises BadConfiguration with collection of errors from calling add_to_combined if any":
            self.sync.register_type("blah", dict, mock.Mock(name="blahkls"))
            self.sync.register_type("other", dict, mock.Mock(name="otherkls"))

            err1, err2, err3 = mock.Mock(name="err1"), mock.Mock(name="err2"), mock.Mock(name="err3")
            err4, err5 = mock.Mock(name="err4"), mock.Mock(name="err5")
            errors = {
                  "blah": [err1, err2]
                , "other": [err3]
                }

            conflicting = [err4, err5]
            fake_find_conflicting = mock.Mock(name="find_conflicting")
            fake_find_conflicting.return_value = conflicting

            fake_add_to_combined = mock.Mock(name="add_to_combined")
            fake_add_to_combined.side_effect = lambda combined, name, *args: errors[name]

            self.sync.add({"blah": {"one": {}, "two": {}}, "other": {"three": {}, "four": {}}, "stuff": ["hmm"]}, "somewhere")

            found = None
            with mock.patch.multiple(self.sync, add_to_combined=fake_add_to_combined, find_conflicting=fake_find_conflicting):
                try:
                    self.sync.combine_configurations()
                    assert False, "Should have raised an error!"
                except BadConfiguration as error:
                    found = error.kwargs["errors"]

            if not found:
                assert False, "Ummm, this isn't right...."

            self.assertEqual(set(found), set([err1, err2, err3, err4, err5]))

        it "Returns merged of combined values":
            self.sync.register_type("blah", dict, mock.Mock(name="blahkls"), key_conflicts_with=["other"])
            self.sync.register_type("other", dict, mock.Mock(name="otherkls"), key_conflicts_with=["blah"])
            self.sync.register_type("stuff", list, mock.Mock(name="sutffkls"))

            self.sync.add({"blah": {"one": {}, "two": {}}, "other": {"three": {}, "four": {}}, "stuff": ["hmm"]}, "somewhere")
            self.sync.add({"blah": {"six": {}}, "other": {"seven": {}}, "stuff": ["yeap"]}, "somewhere2")

            merged = mock.Mock(name="merged")
            fake_merge_combined = mock.Mock("merge_combined")
            fake_merge_combined.return_value = merged

            with mock.patch.object(self.sync, "merge_combined", fake_merge_combined):
                self.assertIs(self.sync.combine_configurations(), merged)

            fake_merge_combined.assert_called_once_with(
                { "blah":
                  { "one": [("somewhere", {})]
                  , "two": [("somewhere", {})]
                  , "six": [("somewhere2", {})]
                  }
                , "other":
                  { "four": [("somewhere", {})]
                  , "three": [("somewhere", {})]
                  , "seven": [("somewhere2", {})]
                  }
                , "stuff":
                  { "hmm": [("somewhere", )]
                  , "yeap": [("somewhere2", )]
                  }
                }
            )

    describe "Merging combined":
        it "removes locations":
            combined = {
                "roles":
                  { "one": [("somewhere", {1: 2})]
                  , "two": [("somewhere", {3: 4})]
                  , "six": [("somewhere2", {5: 6})]
                  }
              , "remove_roles":
                  { "hmm": [("somewhere", )]
                  , "yeap": [("somewhere2", )]
                  }
              }

            merged = {
                "roles":
                  { "one": {1: 2}
                  , "two": {3: 4}
                  , "six": {5: 6}
                  }
              , "remove_roles": ["hmm", "yeap"]
              }

            self.sync.register_default_types()
            self.assertEqual(self.sync.merge_combined(combined), merged)

    describe "Finding conflicting items":
        it "complains about values that are defined multiple places":
            combined = {"key": {"one": [("somewhere", {}), ("somewhere2", {})], "two": [("somewhere", {})]}}
            errors = self.sync.find_conflicting(combined)
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors, [DuplicateItem(key="key", name="one", found=["somewhere", "somewhere2"])])

        it "does not complain about values in list defined in multiple places":
            combined = {"key": {"one": [("somewhere", ), ("somewhere2", )], "two": [("somewhere", )]}}
            self.assertEqual(self.sync.find_conflicting(combined), [])

        it "complains about things that are defined under conflicting keys":
            self.sync.register_type("key", dict, mock.Mock(name="kls"), key_conflicts_with=["key2", "key3"])
            self.sync.register_type("key2", dict, mock.Mock(name="kls"), key_conflicts_with=["key"])
            self.sync.register_type("key3", dict, mock.Mock(name="kls"), key_conflicts_with=["key"])

            combined = {
                  "key":
                  { "one": [("somewhere", {})]
                  , "two": [("somewhere", {})]
                  , "three": [("somewhere3", {})]
                  }
                , "key2":
                  { "one": [("somewhere2", {})]
                  , "three": [("somewhere3", {})]
                  }
                , "key3":
                  { "three": [("somewhere3", {})]
                  }
                }

            errors = self.sync.find_conflicting(combined)
            self.assertSortedEqual(errors
                , [ ConflictingConfiguration("Found item in conflicting specifications", conflicting="one", found_in="somewhere(key); somewhere2(key2)")
                  , ConflictingConfiguration("Found item in conflicting specifications", conflicting="three", found_in="somewhere3(key, key2, key3)")
                  ]
                )

    describe "Adding to combined":
        it "says InvalidConfiguration if the configuration is not the expected type":
            combined = {}
            errors = self.sync.add_to_combined(combined, "key", dict, [1], "somewhere")
            self.assertEqual(errors, [InvalidConfiguration("Expected configuration of a different type", key="key", expected_type=dict, found=list, location="somewhere")])
            self.assertEqual(combined, {})

            errors = self.sync.add_to_combined(combined, "key2", list, {1:2}, "somewhere2")
            self.assertEqual(errors, [InvalidConfiguration("Expected configuration of a different type", key="key2", expected_type=list, found=dict, location="somewhere2")])
            self.assertEqual(combined, {})

        it "complains about duplicates in a list":
            combined = {}
            errors = self.sync.add_to_combined(combined, "key2", list, ["one", "two", "one", "three", "four", "four"], "somewhere2")
            self.assertEqual(errors, [InvalidConfiguration("Found duplicates in a list", key="key2", location="somewhere2", duplicates=["one", "four"])])
            self.assertEqual(combined, {"key2": {}})

        it "records list as a dict of {<thing>: (<location>, )}":
            combined = {}
            errors = self.sync.add_to_combined(combined, "key2", list, ["one", "two", "three", "four"], "somewhere")
            self.assertEqual(errors, [])

            errors = self.sync.add_to_combined(combined, "key2", list, ["one", "five"], "somewhere3")
            self.assertEqual(errors, [])

            self.assertEqual(combined
                , { "key2":
                    { "one": [("somewhere", ), ("somewhere3", )]
                    , "two": [("somewhere", )]
                    , "three": [("somewhere", )]
                    , "four": [("somewhere", )]
                    , "five": [("somewhere3", )]
                    }
                  }
                )

        it "records dict as a dict of {<thing>: (<location>, <val>)}":
            combined = {}
            val1, val2, val3 = mock.Mock(name="val1"), mock.Mock(name="val2"), mock.Mock(name="val3")
            val4, val5, val6 = mock.Mock(name="val4"), mock.Mock(name="val5"), mock.Mock(name="val6")

            errors = self.sync.add_to_combined(combined, "key2", dict, {"one":val1, "two":val2, "three":val3, "four":val4}, "somewhere")
            self.assertEqual(errors, [])

            errors = self.sync.add_to_combined(combined, "key2", dict, {"one":val5, "five":val6}, "somewhere3")
            self.assertEqual(errors, [])

            self.assertEqual(combined
                , { "key2":
                    { "one": [("somewhere", val1), ("somewhere3", val5)]
                    , "two": [("somewhere", val2)]
                    , "three": [("somewhere", val3)]
                    , "four": [("somewhere", val4)]
                    , "five": [("somewhere3", val6)]
                    }
                  }
                )

