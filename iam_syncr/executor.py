from iam_syncr.errors import SyncrError, BadConfiguration, InvalidConfiguration, NoConfiguration
from iam_syncr.amazon.base import Amazon
from iam_syncr.syncer import Sync
from iam_syncr import VERSION

from rainbow_logging_handler import RainbowLoggingHandler
import argparse
import logging
import fnmatch
import yaml
import sys
import os

log = logging.getLogger("iam_sync.executor")

def setup_logging(verbose=False):
    log = logging.getLogger("")
    handler = RainbowLoggingHandler(sys.stderr)
    handler._column_color['%(asctime)s'] = ('cyan', None, False)
    handler._column_color['%(levelname)-7s'] = ('green', None, False)
    handler._column_color['%(message)s'][logging.INFO] = ('blue', None, False)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)-15s %(message)s"))
    log.addHandler(handler)
    log.setLevel([logging.INFO, logging.DEBUG][verbose])

    logging.getLogger("boto").level = logging.CRITICAL

def argparse_readable_folder(value):
    """Argparse type for a readable folder"""
    if not os.path.exists(value):
        raise argparse.ArgumentTypeError("{0} doesn't exist".format(value))
    if not os.path.isdir(value):
        raise argparse.ArgumentTypeError("{0} exists but isn't a folder".format(value))
    if not os.access(value, os.R_OK):
        raise argparse.ArgumentTypeError("{0} exists and is a folder but isn't readable".format(value))
    return os.path.abspath(value)

def make_parser():
    """Make us a parser"""
    parser = argparse.ArgumentParser(description="Sync script, supply your own creds!")
    parser.add_argument("-v", "--verbose"
        , help = "Show debug logging"
        , action = "store_true"
        )

    parser.add_argument("folder"
        , help = "The folder containing the roles we want to sync"
        , type = argparse_readable_folder
        )

    parser.add_argument("--accounts-location"
        , help = "Path to accounts.yaml holding the map of human names to accounts ids"
        )

    parser.add_argument("--filename-match"
        , help = "A glob to match the path of the configuration against (relative to the specified folder)"
        , default = "*.yaml"
        )

    parser.add_argument("--only-consider"
        , help = "Only sync these (i.e. roles, remove_roles, users)"
        , action = "append"
        )

    parser.add_argument("--dry-run"
        , help = "Print out what policies would be set/removed"
        , action = "store_true"
        )

    return parser

def accounts_from(location):
    """Get the accounts dictionary"""
    if not os.path.exists(location):
        raise SyncrError("Could not find an accounts.yaml", location=location)

    if not os.access(location, os.R_OK):
        raise SyncrError("Could not read the accounts.yaml", location=location)

    try:
        accounts = yaml.load(open(location))
    except yaml.parser.ParserError as error:
        raise SyncrError("Failed to parse the accounts yaml file", location=location, error_typ=error.__class__.__name__, error=error)

    for account_id in list(accounts.values()):
        if account_id not in accounts:
            accounts[account_id] = account_id

    return accounts

def make_amazon(folder, accounts_location=None, dry_run=False):
    """Find the account we're using and return a setup Amazon object"""
    if not accounts_location:
        accounts_location = os.path.join(folder, '..', 'accounts.yaml')

    accounts = accounts_from(accounts_location)
    account_name = os.path.basename(folder)

    if account_name not in accounts:
        raise SyncrError("Please add this account to accounts.yaml", accounts_yaml_location=accounts_location, account_name=account_name)
    account_id = accounts[account_name]

    amazon = Amazon(account_id, account_name, accounts, dry_run=dry_run)
    amazon.setup()

    return amazon

def do_sync(amazon, found, only_consider=None):
    """Sync the configuration from this folder"""
    try:
        parsed = parse_configurations(found)
    except BadConfiguration as err:
        log.error("Failed to parse all the yaml specifications")
        for _, error in sorted(err.kwargs["parse_errors"].items()):
            log.error(error)
        raise BadConfiguration()

    sync = Sync(amazon)
    sync.register_default_types()

    if only_consider:
        dont_consider = [considering for considering in only_consider if considering not in sync.types]
        if dont_consider:
            raise SyncrError("Told to sync unknown types", only_sync=list(sync.types.keys()), unknown_types=dont_consider)

    for location, configuration in sorted(parsed.items()):
        sync.add(configuration, location, only_consider)

    try:
        log.info("Combining configuration")
        combined = sync.combine_configurations()
    except BadConfiguration as err:
        log.error("Your configuration didn't make sense")
        for error in err.kwargs["errors"]:
            log.error(error)
        raise BadConfiguration()

    log.info("Starting sync")
    sync.sync(combined)

def parse_configurations(locations):
    """
    Return a dictionary of {location: <parsed_yaml>} for .yaml files in this folder

    Or Raise A BadConfiguration(parse_errors={<location>: <parse_error>})
    With all the errors that are encountered
    """
    parsed = {}
    parse_errors = {}
    for location in locations:
        try:
            config = yaml.load(open(location))
            if not isinstance(config, dict):
                parse_errors[location] = InvalidConfiguration("Configuration is not a dictionary", location=location, found=type(config))
            else:
                parsed[location] = config
        except yaml.parser.ParserError as err:
            parse_errors[location] = InvalidConfiguration("Couldn't parse the yaml", location=location, err_type=err.__class__.__name__, err=err)

    if parse_errors:
        raise BadConfiguration(parse_errors=parse_errors)

    return parsed

def find_configurations(folder, filename_match):
    """Find all the configurations in this folder"""
    found = []
    for root, dirs, files in os.walk(folder):
        for filename in files:
            location = os.path.join(root, filename)
            relative_location = os.path.relpath(location, start=folder)
            if fnmatch.fnmatch(relative_location, filename_match):
                found.append(location)

    if not found:
        raise NoConfiguration(folder=folder)

    return found

def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)

    Amazon.set_boto_useragent("iam_syncr", VERSION)

    try:
        log.info("Making a connection to amazon")
        amazon = make_amazon(folder=args.folder, accounts_location=args.accounts_location, dry_run=args.dry_run)

        log.info("Finding the configuration")
        found = find_configurations(args.folder, args.filename_match)

        log.info("Syncing for account %s from %s", amazon.account_id, args.folder)
        do_sync(amazon, found, args.only_consider)

        if not amazon.changes:
            log.info("No changes were made!")
    except SyncrError as err:
        print("!" * 80)
        print("Something went wrong => {0} |:| {1}".format(err.__class__.__name__, err))
        sys.exit(1)

if __name__ == '__main__':
    main()

