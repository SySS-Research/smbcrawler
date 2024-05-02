import argparse
import getpass

from .lists import LISTS, init_list

try:
    # importlib.metadata is present in Python 3.8 and later
    import importlib.metadata as importlib_metadata
except ImportError:
    # use the shim package importlib-metadata pre-3.8
    import importlib_metadata as importlib_metadata

try:
    __version__ = importlib_metadata.version(__package__ or __name__)
except importlib_metadata.PackageNotFoundError:
    __version__ = "??"

parser = argparse.ArgumentParser(
    description="Search SMB shares for interesting files"
    " (by Adrian Vollmer, SySS GmbH)"
)

parser.add_argument(
    "-V",
    "--version",
    action="version",
    version="smbcrawler %s" % __version__,
)

output_grp = parser.add_argument_group("Input and output")

output_grp.add_argument(
    "-v",
    "--verbose",
    action="count",
    help="increase verbosity of console log by one",
)

output_grp.add_argument(
    "-q",
    "--quiet",
    action="count",
    help="decrease verbosity of console log by one",
)

output_grp.add_argument(
    "-o",
    "--output-dir",
    default=".",
    help="place all output into this directory (default: %(default)s)",
)

output_grp.add_argument(
    "-s",
    "--session-name",
    default="smbcrawler",
    help="basename for output files and directories (default: %(default)s)",
)

output_grp.add_argument(
    "-dS",
    "--disable-share-output",
    default=False,
    action="store_true",
    help="disable the logging of shares to a greppable file",
)

output_grp.add_argument(
    "-dP",
    "--disable-path-output",
    default=False,
    action="store_true",
    help="disable the logging of paths to a greppable file",
)

output_grp.add_argument(
    "-dL",
    "--disable-log-file",
    default=False,
    action="store_true",
    help="disable extensive logging to a file",
)

output_grp.add_argument(
    "-dA",
    "--disable-autodownload",
    default=False,
    action="store_true",
    help="disable autodownload",
)

output_grp.add_argument(
    "-i",
    "--input",
    dest="inputfilename",
    type=str,
    help="input from list of hosts/networks (use - for stdin);"
    " can either be XML output from nmap or a target"
    " specification on each line",
)

output_grp.add_argument(
    dest="target",
    type=str,
    nargs="*",
    help="target specification; can be a host name, a single IP address,"
    " or an IP range in CIDR notation",
)

creds_grp = parser.add_argument_group("Credentials")

creds_grp.add_argument(
    "-u",
    "--user",
    dest="user",
    type=str,
    help="user name, if omitted we'll try a null session",
)


creds_grp.add_argument(
    "-d",
    "--domain",
    type=str,
    default=".",
    help="the user's domain (default: %(default)s)",
)


creds_grp.add_argument(
    "-p",
    "--password",
    dest="password",
    type=str,
    help="password (leave empty for a password prompt)",
)

creds_grp.add_argument(
    "-H",
    "--hash",
    dest="hash",
    type=str,
    help="NTLM hash, can be used instead of a password",
)

creds_grp.add_argument(
    "-f",
    "--force",
    dest="force",
    default=False,
    action="store_true",
    help="always keep going after STATUS_LOGON_FAILURE occurs",
)

crawl_grp = parser.add_argument_group("Crawling options")

crawl_grp.add_argument(
    "-T",
    "--timeout",
    dest="timeout",
    type=int,
    default=5,
    help="Timeout in seconds when attempting to connect to an "
    "SMB service (default: %(default)s)",
)

crawl_grp.add_argument(
    "-t",
    "--threads",
    dest="threads",
    type=int,
    default=1,
    help="Number of parallel threads (default: %(default)s)",
)


crawl_grp.add_argument(
    "-D",
    "--depth",
    dest="depth",
    default=1,
    type=int,
    help="crawling depth; 0 lists only share names and no directories or "
    "files, -1 lists everything (default: %(default)s)",
)


crawl_grp.add_argument(
    "-w",
    "--check-write-access",
    action="store_true",
    default=False,
    help="Check for write access (default: %(default)s)"
    " WARNING: This creates and deletes a directory in the share's"
    " root directory. If you know a better method, let me know.",
)


assess_grp = parser.add_argument_group(
    "Assessment",
    """smbcrawler keeps lists of "interesting" and "boring"
    filenames, directories and shares.
    Files with names that match a regex on the "interesting" list are
    automatically downloaded unless they also match a regex on the
    "boring" list. "Boring" directories are skipped from crawling.
    "Interesting" shares are crawled with depth infinity. "Boring" shares
    are crawled with depth 0 (permissions check only).
    All matches are case-insensitive.""",
)


assess_grp.add_argument(
    "-a",
    "--crawl-printers-and-pipes",
    action="store_true",
    default=False,
    help="Also crawl print queues and IPC pipes (default: %(default)s)",
)


assess_grp.add_argument(
    "-aS",
    "--show",
    choices=LISTS.keys(),
    default="",
    type=str,
    help="Print contents of a list and exit",
)

assess_grp.add_argument(
    "-aR",
    "--show-raw",
    choices=LISTS.keys(),
    default="",
    type=str,
    help="Print contents of a list without comments and exit",
)


assess_grp.add_argument(
    "-aA",
    "--append-list",
    default="",
    nargs="*",
    type=str,
    help=(
        "Append regex to existing list;"
        " listname and regex separated by a colon;"
        " Example: 'interesting_filenames:.*payroll.*'"
    ),
)

assess_grp.add_argument(
    "-aO",
    "--override-list",
    default="",
    nargs="*",
    type=str,
    help=(
        "Replace existing list with this regex;"
        " listname and regex separated by a colon;"
        " Example: 'interesting_filenames:.*payroll.*|.*password.*'"
    ),
)


def output_files_are_writeable(args):
    import os

    # "*.log" not checked because overwriting it would be unexpected to the
    # user. It's not how log files behave.

    filenames = ["secrets.json", "files.json"]

    if not args.disable_share_output:
        filenames.append("shares.grep")

    if not args.disable_path_output:
        filenames.append("paths.grep")

    for filename in filenames:
        if filename:
            path = "%s_%s" % (
                os.path.join(args.output_dir, args.session_name),
                filename,
            )
            try:
                with open(
                    path,
                    "w",
                ) as f:
                    f.write("")
            except Exception as e:
                print(e)
                return False
    return True


def sanity_check(args):
    if not args.target and not args.inputfilename:
        print("You must supply a target or an input filename (or both)")
        exit(1)
    if not output_files_are_writeable(args):
        print(
            "Aborting because output file could not be written. "
            "This is just going to waste everybody's time."
        )
        exit(1)


def parse_args(argv):
    args = parser.parse_args(argv)

    if args.show in LISTS:
        print("Regex\tComment")
        print("===============")
        for each in LISTS[args.show]:
            print("\t".join(each))
        exit(0)
    if args.show_raw in LISTS:
        for each in LISTS[args.show_raw]:
            print(each[0])
        exit(0)
    init_list(args.override_list, args.append_list)

    if args.user and not (args.password is not None or args.hash):
        args.password = getpass.getpass("Enter password: ")

    sanity_check(args)
    return args
