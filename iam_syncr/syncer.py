from iam_syncr.errors import SyncrError, InvalidConfiguration, ConflictingConfiguration, BadConfiguration, DuplicateItem
from iam_syncr.roles import Role, RoleRemoval
from iam_syncr.buckets import Bucket
from iam_syncr.kms import Kms

from collections import defaultdict
import logging

log = logging.getLogger("iam_syncr.syncr")

class Template(object):
    """Thin wrapper to hold templates"""
    def __init__(self, name, template, *args, **kwargs):
        self.name = name
        self.template = template

    def setup(self):
        pass

    def resolve(self):
        pass

class Sync(object):
    """Knows how to interpret configuration for syncing"""

    def __init__(self, amazon):
        self.amazon = amazon

        self.types = {}
        self.the_types = []
        self.templates = {}
        self.configurations = defaultdict(list)

    def sync(self, combined):
        """Let's do this!"""
        for _, name in sorted(self.the_types):
            if name in combined:
                things = self.create_things(combined[name], name)
                self.setup_and_resolve(things)

                # Special case the templates
                if name == "templates":
                    for template in things:
                        self.templates[template.name] = template.template

    def register_default_types(self):
        """Register the default things syncr looks for"""
        self.register_type("templates", dict, Template, priority=0)
        self.register_type("remove_roles", list, RoleRemoval, key_conflicts_with=["roles"], priority=10)
        self.register_type("roles", dict, Role, key_conflicts_with=["remove_roles"], priority=20)
        self.register_type("keys", dict, Kms, priority=30)
        self.register_type("buckets", dict, Bucket, priority=40)

    def register_type(self, name, typ, kls, key_conflicts_with=None, priority=None):
        """
        Register a type to be synced

        Override existing types
        """
        if key_conflicts_with and not isinstance(key_conflicts_with, list):
            key_conflicts_with = [key_conflicts_with]
        self.types[name] = (typ, key_conflicts_with, kls)
        self.the_types.append((priority, name))

    def create_things(self, things, name):
        """Creates a list of objects"""
        typ, _, kls = self.types[name]
        if typ is list:
            return [kls(thing, self.amazon, self.templates) for thing in things]
        else:
            return [kls(thing, val, self.amazon, self.templates) for thing, val in things.items()]

    def setup_and_resolve(self, things):
        """Runs setup on all the provided things and once they are setup, resolve them"""
        for thing in things:
            thing.setup()

        for thing in things:
            thing.resolve()

    def add(self, configuration, location, only_consider=None):
        """Add a new configuration"""
        if not self.types:
            raise SyncrError("Syncr doesn't know about anything, try syncr.register_default_types() first")

        if not isinstance(configuration, dict):
            raise InvalidConfiguration("Configuration needs to be a dict", found=type(configuration))

        for name in self.types:
            if not only_consider or name in only_consider:
                if name in configuration:
                    self.configurations[name].append((location, configuration[name]))

    def combine_configurations(self):
        """
        Return the combination of current configuration

        Or raise BadConfiguration(errors=[<error>, ...])
        """
        errors = []
        combined = {}
        for name, (typ, _, _) in self.types.items():
            for (location, configuration) in self.configurations[name]:
                nxt_errors = self.add_to_combined(combined, name, typ, configuration, location)
                if nxt_errors:
                    errors.extend(nxt_errors)

        conflicting = self.find_conflicting(combined)
        if conflicting:
            errors.extend(conflicting)

        if errors:
            raise BadConfiguration(errors=errors)

        return self.merge_combined(combined)

    def merge_combined(self, combined):
        """Merge our dictionary of {key: {thing: [(location, val), ...]}}"""
        merged = {}
        for key, things in combined.items():
            if things:
                make = self.types[key][0]
                if key not in merged:
                    merged[key] = make()

                for thing, found in things.items():
                    if found:
                        if make is list:
                            merged[key].append(thing)
                        else:
                            merged[key][thing] = found[0][1]

        return merged

    def find_conflicting(self, combined):
        """Return array of ConflictingConfiguration errors for any conflicting values"""
        errors = []
        complained_about = set()
        for key, collections in combined.items():
            for name, found in collections.items():
                if any(len(info) > 1 for info in found) and len(found) > 1:
                    errors.append(DuplicateItem(key=key, name=name, found=[info[0] for info in found]))

        for name, (_, conflicts_with, _) in sorted(self.types.items()):
            if conflicts_with and name in combined and any(conflictor in combined for conflictor in conflicts_with):
                for thing in combined[name]:
                    conflicting = [conflictor for conflictor in conflicts_with if thing in combined.get(conflictor, {})]
                    if any(conflicting):
                        identities = ["{0}{1}".format(category, thing) for category in [name] + conflicting]
                        if all(identity not in complained_about for identity in identities):
                            location_to_keys = defaultdict(set)
                            for key in [name] + conflicting:
                                for vals in combined[key][thing]:
                                    location_to_keys[vals[0]].add(key)

                            found_in = "; ".join(sorted("{0}({1})".format(location, ', '.join(sorted(list(keys)))) for location, keys in location_to_keys.items()))
                            errors.append(ConflictingConfiguration("Found item in conflicting specifications", conflicting=thing, found_in=found_in))
                            for identity in identities:
                                complained_about.add(identity)

        return errors

    def add_to_combined(self, combined, key, expected_type, configuration, location):
        """
        Add the things under this key in the configuration to combined
        And return any errors that are found

        Complain if the key under the configuration is not the expected type

        Make sure to complain about duplicates in keys that are meant to be lists
        Record lists as {<thing>: [<location>, ....]} in combined.

        Record dictionaries in combined as {<thing>: [<location>, <configuration>]}
        """
        errors = []
        if not isinstance(configuration, expected_type):
            errors.append(InvalidConfiguration("Expected configuration of a different type", key=key, expected_type=expected_type, found=type(configuration), location=location))
        else:
            if key not in combined:
                combined[key] = defaultdict(list)

            if expected_type == list:
                track = set()
                duplicates = set()
                for thing in configuration:
                    if thing in track:
                        duplicates.add(thing)
                    else:
                        track.add(thing)

                if duplicates:
                    errors.append(InvalidConfiguration("Found duplicates in a list", key=key, location=location, duplicates=duplicates))
                else:
                    for thing in configuration:
                        combined[key][thing].append((location, ))
            else:
                for thing, val in configuration.items():
                    combined[key][thing].append((location, val))

        return errors

