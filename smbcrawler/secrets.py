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


class NetUser(Secret):
    description = "'net use' command in script"
    regex = 'net use.*/user'
    likely_extensions = ['.ps1', '.bat']


class RunAs(Secret):
    description = "'RunAs' command in script"
    regex = 'runas.*/user'
    likely_extensions = ['.ps1', '.bat']


class SecureString(Secret):
    description = "'ConvertTo-SecureString' command in script"
    regex = 'ConvertTo-SecureString'
    likely_extensions = ['.ps1', '.bat']


class PasswordConfig(Secret):
    description = "'password =' in config"
    regex = '(password|pwd|passwd)[a-z]*\\s*='
    likely_extensions = ['.ini', '.conf', '.cnf', '.config', '.properties']


class PasswordJson(Secret):
    description = "'password' value in JSON file"
    regex = '"[a-z]*(password|pwd|passwd)[a-z]*":'
    likely_extensions = ['.json']


class PasswordYaml(Secret):
    description = "'password' value in YAML file"
    regex = 'passw[a-z]*:'
    likely_extensions = ['.yaml', '.yml']

    def _get_confidence(self):
        # high likelihood of false positives
        c = super()._get_confidence()
        return c - 20


class PasswordXml(Secret):
    description = "'password' element in XML file"
    regex = '<[a-z]*pass[!>]*>[!<]+<[a-z]pass'
    likely_extensions = ['.xml']

    def assess(self):
        result = 90
        _, ext = os.path.splitext(self.filename)
        if self.likely_extensions and \
           ext.lower() not in self.likely_extensions:
            result -= 20
        return result


class PrivateKey(Secret):
    description = 'private key'
    regex = '----- BEGIN[A-Z ]* PRIVATE KEY -----'
    likely_extensions = ['.pem', '.key']


class AwsSecrets(Secret):
    description = 'AWS secrets'
    regex = r'(aws_access_key_id|aws_secret_access_key)\s*='
    likely_extensions = ['.ini']


class EmpirumPassword(Secret):
    description = 'Empirum password'
    regex = r'_PASSWORD_(SETUP|EIS|SYNC)=.'
    likely_extensions = ['.ini']
