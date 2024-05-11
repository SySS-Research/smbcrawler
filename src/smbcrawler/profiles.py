import collections
import re
import os
import pathlib
import glob
import typing
from functools import reduce
from dataclasses import dataclass, field

import xdg.BaseDirectory
import yaml

SCRIPT_PATH = pathlib.Path().resolve()


class Secret(object):
    def __init__(
        self,
        line: str,
        comment: str,
        regex: str,
        regex_flags: list[str] = [],
        false_positives: list[str] = [],
    ) -> None:
        self.line = line
        self.comment = comment
        self.regex = regex
        try:
            self.regex_flags = [getattr(re, flag) for flag in regex_flags]
        except AttributeError:
            self.regex_flags = []
            print("Invalid flags: %s" % self.regex_flags)
        self.false_positives = false_positives

        self.secret = None

        self.match()

    def match(self):
        flags = reduce(lambda x, y: x | y, self.regex_flags)
        match = re.match(f".*{self.regex}.*", self.line, flags=flags)
        if match:
            self.secret = match.groupdict().get("secret", self._line)


class WellKnownThing(typing.TypedDict):
    regex: str
    comment: typing.Optional[str]
    high_value: typing.Optional[bool]
    download: typing.Optional[bool]
    depth: typing.Optional[bool]


@dataclass
class ProfileCollection:
    secrets: dict[str, typing.Optional[Secret]] = field(default_factory=dict)
    shares: dict[str, typing.Optional[WellKnownThing]] = field(default_factory=dict)
    files: dict[str, typing.Optional[WellKnownThing]] = field(default_factory=dict)
    directories: dict[str, typing.Optional[WellKnownThing]] = field(
        default_factory=dict
    )

    def __getitem__(self, key):
        return getattr(self, key)


def deep_update(d, u):
    """Update nested dicts"""
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = deep_update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def update_profile_collection(
    profile_collection: ProfileCollection, new_data: ProfileCollection
) -> None:
    deep_update(profile_collection, new_data)
    for section, items in profile_collection.items():
        for label, keys in items.items():
            if not keys:
                del items[label]


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
            files.append(f)

    result = ProfileCollection()
    for f in files:
        try:
            fp = open(f, "r")
            data = ProfileCollection(yaml.safe_load(fp))
            update_profile_collection(result, data)
        except Exception as e:
            print("Error while parsing file: %s\n%s" % (f, e))

    return result


def find_matching_profile(profile_collection: ProfileCollection, type: str, name: str):
    for label, item in reversed(profile_collection[type].items()):
        if re.match(item["regex"]):
            return item

    defaults = {
        "files": {
            "download": False,
            "high_value": False,
        },
        "shares": {
            "crawl_depth": None,
        },
        "directories": {
            "crawl_depth": None,
        },
        "secrets": None,
    }

    return defaults[type]
