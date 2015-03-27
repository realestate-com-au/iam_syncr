from delfick_error import DelfickError, ProgrammerError

# I use Programmererror, make vim be quiet about it
ProgrammerError = ProgrammerError

class SyncrError(DelfickError): pass

class InvalidDocument(SyncrError):
    desc = "Something wrong with this iam document"

class BadConfiguration(SyncrError):
    desc = "Something wrong with the configuration"

class InvalidConfiguration(SyncrError):
    desc = "Something wrong with this configuration"

class NoConfiguration(SyncrError):
    desc = "Didn't find any yaml files"

class ConflictingConfiguration(SyncrError):
    desc = "The configuration conflicts with itself"

class DuplicateItem(SyncrError):
    desc = "Item defined multiple times"

class BadRole(SyncrError):
    desc = "Bad definition of a role"

class BadPolicy(SyncrError):
    desc = "Bad definition of a policy"

class BadAmazon(SyncrError):
    desc = "Amazon said no"

class CantFindTemplate(SyncrError):
    desc = "Can't find a template"

class NoTemplates(SyncrError):
    desc = "No templates defined"

class BadAlias(SyncrError):
    desc = "Bad kms alias"

