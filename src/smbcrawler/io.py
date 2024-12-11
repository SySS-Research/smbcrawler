import io
import os
import re
import ipaddress
import sys
import hashlib
import logging

from smbcrawler.shares import Target

log = logging.getLogger(__name__)


def parse_targets(s):
    # TODO ipv6
    if re.match(r"^[a-zA-Z0-9-.]+(:[0-9]{1,5})?$", s) or re.match(
        r"^([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?$", s
    ):
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
            if (
                s.port in [445, 139] or s.service in ["netbios-ssn", "microsoft-ds"]
            ) and s.state == "open":
                result.append(h.address)
                break
    return result


def parse_plain_file(filename):
    targets = []
    if filename == "-":
        for line in sys.stdin:
            targets += parse_targets(line)
    else:
        with open(filename, "r") as f:
            for line in f:
                # strip newlines
                targets += parse_targets(line.strip())
    return targets


def get_targets(targets, inputfilename):
    """Load targets from file"""

    _targets = []
    for t in targets:
        _targets += parse_targets(t)

    if inputfilename:
        t = None
        try:
            from libnmap.parser import NmapParserException

            t = parse_xml_file(inputfilename)
        except ImportError:
            log.error("Module 'libnmap' not found, treating as a flat file")
        except NmapParserException:
            log.debug("Not an XML file, treating as flat file")
        if t is None:
            t = parse_plain_file(inputfilename)
        if t:
            _targets += t

    result = [Target(t) for t in _targets]
    log.info("Loaded %s hosts" % len(result))
    return result


def get_hash(data):
    hash_object = hashlib.sha256(data)
    content_hash = hash_object.hexdigest()
    return content_hash


def get_hash_of_file(path):
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    sha = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()


def decode_bytes(data, file_type):
    """Decode bytes from all encodings"""

    if "UTF-8 (with BOM)" in file_type:
        return data.decode("utf-8-sig", errors="replace")
    elif "UTF-16 (with BOM)" in file_type:
        return data.decode("utf-16", errors="replace")
    elif "UTF-16, little-endian" in file_type:
        return data.decode("utf-16", errors="replace")
    elif "UTF-16, big-endian" in file_type:
        return data.decode("utf-16", errors="replace")
    elif "ASCII text" in file_type:
        return data.decode(errors="replace")
    return data.decode(errors="replace")


def convert(data, mime, file_type):
    """Convert bytes to string"""

    if mime.endswith("charset-binary") or file_type.endswith("data"):
        if mime.startswith("application/pdf"):
            import pdftotext

            with io.BytesIO(data) as fp:
                pdf = pdftotext.PDF(fp)
            return "\n\n".join(pdf)
        else:
            # TODO convert docx, xlsx
            return ""
    else:
        return decode_bytes(data, file_type)


def find_secrets(content, secret_profiles):
    """Extract secrets from content"""
    result = []

    for line_number, line in enumerate(content.splitlines()):
        if not line or len(line) > 1024:
            continue

        # find secret
        for s in secret_profiles.values():
            s.match(line)
            if s.secret:
                result.append(
                    {
                        "secret": s.secret.strip(),
                        "line": line.strip(),
                        "line_number": line_number + 1,
                        "comment": s.comment,
                    }
                )

    return result


def sanitize(remark):
    """Remove unwanted characters"""
    result = "".join([x for x in remark if ord(x) >= 32])
    return result


def create_link(target, share, path, src, dst):
    local_path = os.path.join(dst, "tree")
    for part in [target, share] + path.split("\\"):
        os.makedirs(local_path, exist_ok=True)
        local_path = os.path.join(local_path, part)
        src = os.path.join("..", src)
    src = os.path.join("..", src)
    os.symlink(src, local_path)
