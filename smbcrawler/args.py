import argparse
import getpass

from .lists import LISTS, init_list
from ._version import __version__

parser = argparse.ArgumentParser(
    description="Search SMB shares for interesting files"
                " (by Adrian Vollmer, SySS GmbH)"
)

parser.add_argument(
    '-V', '--version', action='version',
    version='smbcrawler %s' % __version__,
)

output_grp = parser.add_argument_group("Input and output")

output_grp.add_argument(
    "-v", "--verbose",
    action="count",
    help="Increase verbosity by one",
)

output_grp.add_argument(
    "-q", "--quiet",
    action="count",
    help="Decrease verbosity by one",
)

output_grp.add_argument(
    '-oN',
    dest="no_output",
    default=False,
    action='store_true',
    help="proceed without writing output to any file"
)

output_grp.add_argument(
    '-oX',
    dest="outputfilename_xml",
    type=str,
    help="output in XML format to the given filename"
)

output_grp.add_argument(
    '-oJ',
    dest="outputfilename_json",
    type=str,
    help="output in JSON format to the given filename"
)

output_grp.add_argument(
    '-oG',
    dest="outputfilename_grep",
    type=str,
    help="output in grepable format to the given filename"
)

output_grp.add_argument(
    '-oL',
    dest="outputfilename_log",
    type=str,
    help="write the log at the INFO level to the given filename"
)

output_grp.add_argument(
    '-oD',
    dest="outputdirname",
    default="autodownload",
    type=str,
    help="directory to put auto-downloaded files in"
)

output_grp.add_argument(
    '-oA',
    dest="outputfilename_all",
    type=str,
    help="output in all formats to the given filename"
)

output_grp.add_argument(
    dest="target",
    type=str,
    nargs="*",
    help="target specification; can be a host name, a single IP address,"
         " or an IP range in CIDR notation"
)

output_grp.add_argument(
    '-i', '--input',
    dest="inputfilename",
    type=str,
    help="input from list of hosts/networks (use - for stdin);"
         " can either be XML output from nmap or a target"
         " specification on each line"
)

creds_grp = parser.add_argument_group("Credentials")

creds_grp.add_argument(
    '-u', '--user',
    dest="user",
    type=str,
    help="user name, if omitted we'll try a null session"
)


creds_grp.add_argument(
    '-d', '--domain',
    dest="domain",
    type=str,
    default='.',
    help="the user's domain"
         " (default: %(default)s)"
)


creds_grp.add_argument(
    '-p', '--password',
    dest="password",
    type=str,
    help="password (leave empty for a password prompt)"
)

creds_grp.add_argument(
    '-H', '--hash',
    dest="hash",
    type=str,
    help="NTLM hash, can be used instead of a password"
)

creds_grp.add_argument(
    '-f', '--force',
    dest="force",
    default=False,
    action='store_true',
    help="always keep going after STATUS_LOGON_FAILURE occurs"
)

crawl_grp = parser.add_argument_group("Crawling options")

crawl_grp.add_argument(
    '-T', '--timeout',
    dest="timeout",
    type=int,
    default=5,
    help="Timeout in seconds when attempting to connect to an "
         "SMB service (default: %(default)s)"
)

crawl_grp.add_argument(
    '-t', '--threads',
    dest="threads",
    type=int,
    default=1,
    help="Number of parallel threads (default: %(default)s)"
)


crawl_grp.add_argument(
    '-D', '--depth',
    dest="spider_depth",
    default=1,
    type=int,
    help="spider depth; 0 lists only share names and no directories, -1"
         " lists everything (default: %(default)s)"
)


crawl_grp.add_argument(
    '-w', '--check-write-access',
    action='store_true',
    default=False,
    help="Check for write access (default: %(default)s)"
         " WARNING: This creates and deletes a directory in the share's"
         " root directory. If you know a better method, let me know."
)


assess_grp = parser.add_argument_group(
    "Assessment",
    """smbcrawler keeps four lists: a list of \"interesting\" and \"boring\"
    filenames and a list of \"interesting\" and \"boring\" share names.
    Files with names that match a regex on the \"interesting\" list are
    automatically downloaded unless they also match a regex on the
    \"boring\" list. \"Interesting\" shares are crawled with depth infinity.
    \"Boring\" shares are crawled with depth 0 (permissions check only).
    All matches are case-insensitive."""
)


assess_grp.add_argument(
    '-a', '--crawl-printers-and-pipes',
    action='store_true',
    default=False,
    help="Also crawl print queues and IPC pipes (default: %(default)s)"
)


assess_grp.add_argument(
    '-aS', '--show',
    choices=LISTS.keys(),
    default="",
    type=str,
    help="Print contents of a list and exit"
)

assess_grp.add_argument(
    '-aR', '--show-raw',
    choices=LISTS.keys(),
    default="",
    type=str,
    help="Print contents of a list without comments and exit"
)


assess_grp.add_argument(
    '-aA', '--append-list',
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
    '-aO', '--override-list',
    default="",
    nargs="*",
    type=str,
    help=(
        "Replace existing list with this regex;"
        " listname and regex separated by a colon;"
        " Example: 'interesting_filenames:.*payroll.*|.*password.*'"
    ),
)


def parse_args(argv):
    global args  # TODO don't use global arguments
    global original_args
    original_args = argv
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

    if args.outputfilename_all:
        args.outputfilename_xml = args.outputfilename_all
        args.outputfilename_json = args.outputfilename_all
        args.outputfilename_log = args.outputfilename_all
        #  args.outputfilename_normal = args.outputfilename_all
        args.outputfilename_grep = args.outputfilename_all
        args.outputdirname = args.outputfilename_all + "-autodownload"

    if args.outputfilename_xml:
        args.outputfilename_xml += ".xml"
    if args.outputfilename_json:
        args.outputfilename_json += ".json"
    if args.outputfilename_log:
        args.outputfilename_log += ".log"
    #  if args.outputfilename_normal:
    #      args.outputfilename_normal += ".txt"
    if args.outputfilename_grep:
        args.outputfilename_grep += ".grep"

    return args
