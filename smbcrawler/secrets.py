import re
import os
from functools import reduce


class Secret(object):
    likely_extensions = []
    regex_flags = [re.IGNORECASE]
    regex = ''

    def __init__(self, line, mimetype=None, filename=None):
        self.line = line
        self.mimetype = mimetype
        self.filename = filename
        self.confidence = 0
        self.match_result = None

    def description(self):
        """Must return a short string"""
        assert self.description
        return self.description

    def _get_confidence(self):
        """Must return an integer between 0 and 100 based on self.line

        0 means: nothing found. 100 means: certainly a password.
        """
        flags = reduce(lambda x, y: x | y, self.regex_flags)
        m = re.search(self.regex, self.line, flags=flags)
        if m:
            result = self.assess()
            self.match_result = m
            return result
        return 0

    def assess(self):
        # long lines are unlikely in scripts and configs
        result = 90
        if len(self.line) > 512:
            result -= 30
        _, ext = os.path.splitext(self.filename)
        if self.likely_extensions and \
           ext.lower() not in self.likely_extensions:
            result -= 20
        if 'data' in self.mimetype:
            result -= 20
        self.confidentiality = result
        return result

    def get_confidence(self):
        result = self._get_confidence()
        if result < 0:
            result = 0
        if result > 100:
            result = 100
        result = int(result)
        self.confidence = result
        return result

    def get_secret(self):
        if self.match_result:
            return self.match_result.groupdict().get('secret', '')
        return ""

    def get_line(self):
        if self.match_result:
            return self.match_result.group(0).strip()
        return ""


class NetUser(Secret):
    description = "'net use' command in script"
    regex = 'net use.*/user.*'
    likely_extensions = ['.ps1', '.bat', '.cmd']


class RunAs(Secret):
    description = "'RunAs' command in script"
    regex = 'runas.*/user'
    likely_extensions = ['.ps1', '.bat', '.cmd']


class SecureString(Secret):
    description = "'ConvertTo-SecureString' command in script"
    regex = 'ConvertTo-SecureString'
    likely_extensions = ['.ps1', '.bat', '.cmd']


class PasswordConfig(Secret):
    description = "'password =' in config"
    regex = '(password|pwd|passwd)[a-z]*\\s*=\\s*(?P<secret>..+)'
    likely_extensions = ['.ini', '.conf', '.cnf', '.config', '.properties']

    def assess(self):
        # some common strings that cause false positive
        c = super().assess()
        if (
            'ShowPasswordDialog=' in self.get_line()
            or 'DisableChangePassword=' in self.get_line()
        ):
            c = 0
        return c


class PasswordJson(Secret):
    description = "'password' value in JSON file"
    regex = '"[a-z]*(password|pwd|passwd)[a-z]*":"(?P<secret>..+)"'
    likely_extensions = ['.json']

    def assess(self):
        # some strings in adml files on SYSVOL make it a sure false positive
        c = super().assess()
        if (
            'DisableChangePassword=' in self.get_line()
        ):
            c = 0
        return c


class PasswordYaml(Secret):
    description = "'password' value in YAML file"
    regex = '\\s*[a-z]*passw[a-z]*:\\s*(?P<secret>..+)'
    likely_extensions = ['.yaml', '.yml']

    def assess(self):
        # high likelihood of false positives
        c = super().assess()
        return c - 30


class PasswordXml(Secret):
    description = "'password' element in XML file"
    regex = '<[a-z]*pass[!>]*>(?P<secret>[!<]+)</[a-z]*pass'
    likely_extensions = ['.xml']

    def assess(self):
        result = 90
        _, ext = os.path.splitext(self.filename)
        if self.likely_extensions and \
           ext.lower() not in self.likely_extensions:
            result -= 20
        # cpassword very likely
        if "<cpassword>" in self.get_line():
            result = 95
        return result


class PasswordUnattend(Secret):
    description = "password in unattend.xml"
    regex = r'<Password>\s*<Value>(?P<secret>[!<]+)</Value'

    def assess(self):
        return 97


class PrivateKey(Secret):
    description = 'private key'
    regex = '----- BEGIN[A-Z ]* PRIVATE KEY -----'
    likely_extensions = ['.pem', '.key']


class UrlPassword(Secret):
    description = 'URL Password'
    regex = r'[a-z0-9]://(?P<secret>[^:]+:[^@])@[a-z0-9]'


class AwsSecrets(Secret):
    description = 'AWS secrets'
    regex = r'(aws_access_key_id|aws_secret_access_key)\s*=\s*(?P<secret>..+)'
    likely_extensions = ['.ini']


class EmpirumPassword(Secret):
    description = 'Empirum password (Matrix42)'
    regex = r'_PASSWORD_(SETUP|EIS|SYNC)=(?P<secret>..+)'
    likely_extensions = ['.ini']

    def assess(self):
        # high likelihood of false positives
        c = super().assess()
        c += 20
        return c


class DsmPassword(Secret):
    description = 'DSM password (Ivanti/Frontrange)'
    regex = r'k[23456][A-Za-z0-9+/]{16,}=?=?|K1[A-Z0-9;/]{16,}'
    likely_extensions = ['.ncp']
    regex_flags = []
