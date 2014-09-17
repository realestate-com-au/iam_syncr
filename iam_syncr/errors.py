class SyncrError(Exception):
    """Helpful class for creating custom exceptions"""
    desc = ""

    def __init__(self, message="", **kwargs):
        self.kwargs = kwargs
        self.message = message
        super(SyncrError, self).__init__(message)

    def __str__(self):
        desc = self.desc
        message = self.message

        info = ["{0}={1}".format(k, v) for k, v in sorted(self.kwargs.items())]
        info = '\t'.join(info)
        if info and (message or desc):
            info = "\t{0}".format(info)

        if desc:
            if message:
                message = ". {0}".format(message)
            return '"{0}{1}"{2}'.format(desc, message, info)
        else:
            if message:
                return '"{0}"{1}'.format(message, info)
            else:
                return "{0}".format(info)

    def __eq__(self, error):
        """Say whether this error is like the other error"""
        return error.__class__ == self.__class__ and error.message == self.message and error.kwargs == error.kwargs

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

