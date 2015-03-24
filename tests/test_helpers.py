# coding: spec

from iam_syncr.helpers import listify, listified, as_list

import six

from tests.helpers import TestCase

if six.PY2:
    import mock
else:
    from unittest import mock

describe TestCase, "listify":
    it "sets the key in the dct to an empty array if doesn't exist and returns it":
        dct = {}
        lst = listify(dct, "blah")
        self.assertIs(lst, dct["blah"])

    it "returns the key as is if already a list":
        lst = [1, 2]
        dct = {"blah": lst}
        self.assertIs(listify(dct, "blah"), lst)
        self.assertEqual(dct, {"blah": lst})

    it "makes the key a list and returns if in there but not a list already":
        for val in (0, 1, None, True, False, "", "adf", lambda: 1, mock.Mock(name="blah")):
            dct = {"blah": val}
            lst = listify(dct, "blah")
            self.assertEqual(lst, [val])
            self.assertEqual(dct, {"blah": lst})

describe TestCase, "listified":
    it "yields nothing if the key isn't in the dict":
        self.assertEqual(list(listified({"meh": 1}, "blah")), [])

    it "yields the thing if the thing is not a list":
        for val in (0, 1, None, True, False, "", "adf", lambda: 1, mock.Mock(name="blah")):
            self.assertEqual(list(listified({"blah": val}, "blah")), [val])

    it "yields the items in the thing if the thing is a list":
        item1 = 3
        item2 = 1
        item3 = 2
        lst = [item1, item2, item3]
        self.assertEqual(list(listified({"blah": lst}, "blah")), [item1, item2, item3])

describe TestCase, "as_list":
    it "yields the things in the thing if it's a list":
        lst = [1, 2]
        self.assertEqual(list(as_list(lst)), lst)

    it "yields just the thing if not a list":
        for val in (0, 1, None, True, False, "", "adf", lambda: 1, mock.Mock(name="blah")):
            self.assertEqual(list(as_list(val)), [val])

