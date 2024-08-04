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

        try:
            self.regex_flags = [getattr(re, flag) for flag in regex_flags]
        except AttributeError:
            log.error("Invalid flags: %s" % self.regex_flags)
            self.regex_flags = []

        if self.regex_flags:
            flags = reduce(lambda x, y: x | y, self.regex_flags)
        else:
            flags = 0

        self.regex = re.compile(".*" + regex + ".*", flags=flags)

        self.false_positives = false_positives

        self.secret = None
        self.line = None

    def match(self, line):
        self.line = line

        match = self.regex.match(line)

        if match:
            self.secret = match.groupdict().get("secret", self.line)
        else:
            self.secret = None

        if self.secret in self.false_positives:
            self.secret = None


class WellKnownThing(typing.TypedDict):
    regex: str
    regex_flags: typing.Optional[list[str]]
    comment: typing.Optional[str]
    high_value: typing.Optional[bool]
    download: typing.Optional[bool]
    depth: typing.Optional[bool]
    crawl_depth: typing.Optional[int]


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

    def as_dict(self):
        data = {}
        for k in self.keys():
            data[k] = self[k]
        return data

    def __str__(self):
        result = yaml.dump(self.as_dict())
        return result

    def __repr__(self):
        return str(self)


def deep_update(d, u):
    """Update nested dicts"""
    for k in u.keys():
        if isinstance(u[k], collections.abc.Mapping):
            d[k] = deep_update(d.get(k, {}), u[k])
        else:
            d[k] = u[k]
    return d


def collect_profiles(
    extra_dirs: list[str] = [],
    extra_files: list[str] = [],
    update_queries: list[str] = [],
) -> ProfileCollection:
    """Search directories for profile files"""
    dirs = [
        xdg.BaseDirectory.save_config_path("smbcrawler"),
        os.getcwd(),
    ]

    for d in extra_dirs:
        dirs.append(d)

    files = [
        SCRIPT_PATH / "default_profile.yml",
    ]

    for d in dirs:
        for f in glob.glob(str(pathlib.Path(d) / "*.yml")):
            files.append(pathlib.Path(d) / f)

    files.extend(map(pathlib.Path, extra_files))

    result: dict[str, object] = {}

    for f in map(str, files):
        try:
            with open(f, "r") as fp:
                data = yaml.safe_load(fp)
        except Exception as e:
            print("Error while parsing file: %s\n%s" % (f, e))
        else:
            result = deep_update(result, data)

    for q in update_queries:
        path, value = q.split("=")
        update_nested_dict(result, path, value)

    return ProfileCollection(result)


def parse_access_path(path):
    # Regular expression to match keys, including those in quotes
    key_regex = re.compile(r'(?:\[["\'](.*?)["\']\])|([^.]+)')

    keys = []
    for match in key_regex.finditer(path):
        if match.group(1):
            # If the key is in quotes, handle escaped quotes
            keys.append(
                match.group(1)
                .replace('\\"', '"')
                .replace("\\'", "'")
                .replace("\\\\", "\\")
            )
        else:
            keys.append(match.group(2))
    return keys


def update_nested_dict(nested_dict, path, value):
    keys = parse_access_path(path)
    d = nested_dict
    for key in keys[:-1]:
        d = d.setdefault(key, {})
    d[keys[-1]] = value


def find_matching_profile(profile_collection: ProfileCollection, type: str, name: str):
    for label, item in reversed(profile_collection[type].items()):
        try:
            regex_flags = [getattr(re, flag) for flag in item.get("regex_flags", [])]
        except AttributeError:
            log.error("Invalid flags: %s" % regex_flags)
            regex_flags = []
        if regex_flags:
            flags = reduce(lambda x, y: x | y, regex_flags)
        else:
            flags = 0
        if re.match(item["regex"], name, flags=flags):
            return item
