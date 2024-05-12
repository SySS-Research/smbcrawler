import collections
import re
import os
import pathlib
import glob
import logging
import typing
from functools import reduce

import xdg.BaseDirectory
import yaml

SCRIPT_PATH = pathlib.Path(__file__).parent.resolve()
log = logging.getLogger(__name__)


class Secret(object):
    def __init__(
        self,
        comment: str,
        regex: str,
        regex_flags: list[str] = [],
        false_positives: list[str] = [],
    ) -> None:
        self.comment = comment
        self.regex = regex
        try:
            self.regex_flags = [getattr(re, flag) for flag in regex_flags]
        except AttributeError:
            self.regex_flags = []
            log.error("Invalid flags: %s" % self.regex_flags)
        self.false_positives = false_positives

        self.secret = None
        self.line = None

    def match(self, line):
        self.line = line
        if self.regex_flags:
            flags = reduce(lambda x, y: x | y, self.regex_flags)
        else:
            flags = 0
        match = re.match(f".*{self.regex}.*", line, flags=flags)
        if match:
            self.secret = match.groupdict().get("secret", self.line)
        else:
            self.secret = None


class WellKnownThing(typing.TypedDict):
    regex: str
    comment: typing.Optional[str]
    high_value: typing.Optional[bool]
    download: typing.Optional[bool]
    depth: typing.Optional[bool]


class ProfileCollection(object):
    def __init__(self, data):
        self.secrets = {}
        self.shares = {}
        self.files = {}
        self.directories = {}

        for label, secret in data.get("secrets", {}).items():
            self.secrets[label] = Secret(**secret)

        for thing in ["shares", "files", "directories"]:
            for label, item in data.get(thing, {}).items():
                self[thing][label] = WellKnownThing(**item)

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        return setattr(self, key, value)

    def keys(self):
        return ("secrets", "shares", "files", "directories")

    def get(self, k, default):
        return getattr(self, k, default)


def deep_update(d, u):
    """Update nested dicts"""
    for k in u.keys():
        if isinstance(u[k], collections.abc.Mapping):
            d[k] = deep_update(d.get(k, {}), u[k])
        else:
            d[k] = u[k]
    return d


def collect_profiles(extra_dir: typing.Optional[str] = None) -> ProfileCollection:
    """Search directories for profile files"""
    dirs = [
        xdg.BaseDirectory.save_config_path("smbcrawler"),
        os.getcwd(),
    ]

    if extra_dir:
        dirs.append(extra_dir)

    files = [
        SCRIPT_PATH / "default_profile.yml",
    ]

    for d in dirs:
        for f in glob.glob(str(pathlib.Path(d) / "*.yml")):
            files.append(os.path.join(d, f))

    result = {}
    for f in files:
        try:
            fp = open(f, "r")
            data = yaml.safe_load(fp)
        except Exception as e:
            print("Error while parsing file: %s\n%s" % (f, e))
        else:
            result = deep_update(result, data)

    return ProfileCollection(result)


def find_matching_profile(profile_collection: ProfileCollection, type: str, name: str):
    for label, item in reversed(profile_collection[type].items()):
        if re.match(item["regex"], name):
            return item
