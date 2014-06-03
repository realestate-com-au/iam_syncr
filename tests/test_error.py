# coding: spec

from iam_syncr.errors import SyncrError
from unittest import TestCase

describe TestCase, "SyncrError":
    it "creates a message that combines desc on the class, args and kwargs":
        error = SyncrError("The syncing was bad", a=4, b=5)
        self.assertEqual(str(error), '"The syncing was bad"\ta=4\tb=5')

    it "Works without a message":
        error = SyncrError(a_thing=4, b=5)
        self.assertEqual(str(error), 'a_thing=4\tb=5')

    it "works with subclasses of SyncrError":
        class OtherSyncingErrors(SyncrError):
            desc = "Oh my!"
        error = OtherSyncingErrors("hmmm", d=8, e=9)
        self.assertEqual(str(error), '"Oh my!. hmmm"\td=8\te=9')

        error2 = OtherSyncingErrors(f=10, g=11)
        self.assertEqual(str(error2), '"Oh my!"\tf=10\tg=11')

    it "can tell if an error is equal to another error":
        class Sub1(SyncrError):
            desc = "sub"
        class Sub2(SyncrError):
            desc = "sub"

        self.assertNotEqual(Sub1("blah"), Sub2("blah"))
        self.assertNotEqual(Sub1("blah", one=1), Sub1("blah", one=2))

        self.assertEqual(Sub1("blah"), Sub1("blah"))
        self.assertEqual(Sub1("blah", one=1, two=2), Sub1("blah", two=2, one=1))

