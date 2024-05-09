import collections
import re
import os
import pathlib
import glob
import typing
from functools import reduce

import xdg.BaseDirectory
import yaml

SCRIPT_PATH = pathlib.Path().resolve()


class Secret(object):
    def __init__(
        self,
        file_contents: str,
        comment: str,
        regex: str,
        regex_flags: list[str] = [],
        false_positives: list[str] = [],
    ) -> None:
        self.file_contents = file_contents
        self.comment = comment
        self.regex = regex
        try:
            self.regex_flags = [getattr(re, flag) for flag in regex_flags]
        except AttributeError:
            self.regex_flags = []
            print("Invalid flags: %s" % self.regex_flags)
        self.false_positives = false_positives

        self._line = None
        self._secret = None

    def match(self):
        flags = reduce(lambda x, y: x | y, self.regex_flags)
        match = re.match(f".*{self.regex}.*", self.file_contents, flags=flags)
        if match:
            self._line = match.group(0).strip()
            self._secret = match.groupdict().get("secret", self._line)

    @property
    def secret(self):
        return self._secret

    @property
    def line(self):
        return self._line


class WellKnownThing(typing.TypedDict):
    regex: str
    comment: typing.Optional[str]
    high_value: typing.Optional[bool]
    download: typing.Optional[bool]
    depth: typing.Optional[bool]


class ProfileCollection(collections.defaultdict):
    secrets: dict[str, typing.Optional[Secret]]
    shares: dict[str, typing.Optional[WellKnownThing]]
    files: dict[str, typing.Optional[WellKnownThing]]
    directories: dict[str, typing.Optional[WellKnownThing]]


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
        for f in glob.glob(pathlib.Path(d) / "*.yml"):
            files.append(f)

    result = ProfileCollection(collections.defaultdict(lambda: []))
    for f in files:
        try:
            fp = open(f, "r")
            data = ProfileCollection(yaml.safe_load(fp))
            update_profile_collection(result, data)
        except Exception as e:
            print("Error while parsing file: %s\n%s" % (f, e))

    return result
