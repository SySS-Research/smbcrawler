import os
import io
import re
import ipaddress
import sys
import hashlib
import collections
import logging
import json

import magic

from smbcrawler.shares import Target
from smbcrawler.secrets import Secret

log = logging.getLogger(__name__)

HASHED_FILES = collections.defaultdict(lambda: [])
SECRETS = collections.defaultdict(lambda: [])


def parse_targets(s):
    if (re.match(r"^[a-zA-Z0-9-.]+(:[0-9]{1,5})?$", s) or
            re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?$", s)):
        # single ip or host name
        return [s]
    elif re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$", s):
        # ip range
        net = ipaddress.ip_network(s, False)
        return [str(ip) for ip in net.hosts()]
    else:
        log.error("Invalid host name or IP address: %s" % s)
        return []


def parse_xml_file(filename):
    from libnmap.parser import NmapParser

    if filename == "-":
        content = sys.stdin.read()
        nmap_report = NmapParser.parse_fromstring(content)
    else:
        nmap_report = NmapParser.parse_fromfile(filename)
    result = []
    for h in nmap_report.hosts:
        for s in h.services:
            if (s.port in [445, 139] or
                    s.service in ['netbios-ssn', 'microsoft-ds']):
                result.append(h.address)
                break
    return result


def parse_plain_file(filename):
    targets = []
    if filename == "-":
        for line in sys.stdin:
            targets += parse_targets(line)
    else:
        with open(filename, 'r') as f:
            for line in f:
                # strip newlines
                targets += parse_targets(line.strip())
    return targets


def get_targets(target, inputfilename, timeout):
    """"Load targets from file"""

    targets = []
    for t in target:
        targets += parse_targets(t)
    if inputfilename:
        t = []
        try:
            from libnmap.parser import NmapParserException
            t = parse_xml_file(inputfilename)
        except ImportError:
            log.error("Module 'libnmap' not found, treating as a flat file")
        except NmapParserException:
            log.debug("Not an XML file, treating as flat file")
        if not t:
            t = parse_plain_file(inputfilename)
        if t:
            targets += t
    return [Target(t, timeout) for t in targets]


def save_file(dirname, data, host, share, path):
    # Check if file is already known
    hash_object = hashlib.sha256(data)
    # 4 bytes should be enough
    content_hash = hash_object.hexdigest()[:8]
    seen = content_hash in HASHED_FILES
    URI = '\\'.join(['', '', host, share, path])
    HASHED_FILES[content_hash].append(URI)
    if seen:
        log.info("File already seen, discarding: %s" % URI)
        return

    if not os.path.exists(dirname):
        os.makedirs(dirname)

    filename = "%s:\\\\%s\\%s\\%s" % (content_hash, host, share, path)
    path = os.path.join(dirname, filename)

    # Make sure not to overwrite files, append a number
    if os.path.exists(path):
        count = 1
        while os.path.isfile("%s.%d" % (path, count)):
            count += 1
        path = "%s.%d" % (path, count)

    find_secrets(data, path, content_hash)
    # Write data to disk
    with open(path, 'wb') as f:
        f.write(data)


def decode_bytes(data, file_type):
    """Decode bytes from all encodings"""

    if 'UTF-8 (with BOM)' in file_type:
        return data.decode('utf-8-sig', errors='replace')
    elif 'UTF-16 (with BOM)' in file_type:
        return data.decode('utf-16', errors='replace')
    elif 'UTF-16, little-endian' in file_type:
        return data.decode('utf-16', errors='replace')
    elif 'UTF-16, big-endian' in file_type:
        return data.decode('utf-16', errors='replace')
    elif 'ASCII text' in file_type:
        return data.decode(errors='replace')
    return data.decode(errors='replace')


def convert(data, mime, file_type):
    """Convert bytes to string"""

    if mime.endswith('charset-binary') or file_type.endswith('data'):
        if mime.startswith('application/pdf'):
            import pdftotext
            with io.BytesIO(data) as fp:
                pdf = pdftotext.PDF(fp)
            return '\n\n'.join(pdf)
        else:
            # TODO convert docx, xlsx
            return ''
    else:
        return decode_bytes(data, file_type)


def find_secrets(data, filename, content_hash):
    """Extract secrets from byes"""

    mime = magic.from_buffer(data, mime=True)
    file_type = magic.from_buffer(data)
    try:
        data = convert(data, mime, file_type)
    except Exception:
        return

    for line in data.splitlines():
        if not line:
            continue
        secret = None
        # find secret with max confidence
        for s in Secret.__subclasses__():
            s = s(line, mimetype=mime, filename=filename)
            c = s.get_confidence()
            if (not secret and c > 0) or (secret and c > secret.confidence):
                secret = s
        if secret and secret.confidence > 0:
            log.success(
                "Found secret (`%s`, confidence %d) in [%s] %s: %s" % (
                    secret.description,
                    secret.confidence,
                    content_hash,
                    secret.filename,
                    secret.line,
                )
            )
            SECRETS[content_hash].append([
                secret.description,
                secret.confidence,
                secret.line,
            ])


def write_secrets(path):
    with open(path, 'w') as fp:
        # Make copy of dict for thread safety
        json.dump(dict(SECRETS), fp)


def write_files(path):
    with open(path, 'w') as fp:
        # Make copy of dict for thread safety
        json.dump(dict(HASHED_FILES), fp)


def sanitize(remark):
    """Remove unwanted characters"""
    result = ''.join([x for x in remark if ord(x) >= 32])
    return result


def to_grep_line(values):
    result = '\t'.join([sanitize(str(x)) for x in values])
    return result
