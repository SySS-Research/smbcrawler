import argparse

from ._version import __version__

parser = argparse.ArgumentParser(
    description="Search local files for secrets" " (by Adrian Vollmer, SySS GmbH)"
)

parser.add_argument(
    "-V",
    "--version",
    action="version",
    version="smbcrawler %s" % __version__,
)

parser.add_argument(
    "-o",
    "--output",
    default="-",
    type=argparse.FileType(mode="w"),
    help="path to an output file (default: %(default)s)",
)

parser.add_argument(
    "paths",
    type=str,
    nargs="+",
    help="paths to files and directories to search for secret",
)

parser.add_argument(
    "-r",
    "--recursive",
    default=False,
    action="store_true",
    help="enable recursive directory search (default: %(default)s)",
)

parser.add_argument(
    "-j",
    "--as-json",
    default=False,
    action="store_true",
    help="interpret the input files as *_secrets.json and don't crawl "
    "for secrets again",
)

parser.add_argument(
    "-f",
    "--format",
    default="json",
    choices=["json", "html"],
    help="enable recursive directory search (default: %(default)s)",
)


def parse_args(argv=None):
    args = parser.parse_args(argv)
    return args
