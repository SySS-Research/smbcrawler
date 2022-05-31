import os
import re
import ipaddress
import json
import sys
from lxml import etree as ET
import logging

from impacket.smbconnection import SMBConnection
from impacket.smb import SharedFile
from smbcrawler.shares import Target, SMBShare

log = logging.getLogger(__name__)


class DataCollector(object):
    def __init__(self, args):
        self.args = args
        self.hosts = []

    def __iter__(self):
        return iter(self.hosts)

    def add_smbhost(self, smbClient):
        if smbClient not in self:
            self.hosts.append(smbClient)

    def write_output(self):
        log.info("Writing output...")
        if self.args.outputfilename_grep:
            write_grep(self, self.args.outputfilename_grep)
        if self.args.outputfilename_xml:
            write_xml(self, self.args.outputfilename_xml)
        if self.args.outputfilename_json:
            write_json(self, self.args.outputfilename_json)
        #  if self.args.outputfilename_normal:
        #      write_normal(output)


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, DataCollector):
            return {str(smbClient): smbClient for smbClient in obj.hosts}
        elif isinstance(obj, SMBConnection):
            return {share.name: share for share in obj.shares}
        elif isinstance(obj, SMBShare):
            result = {}
            result["paths"] = {path.get_full_path(): path
                               if path.is_directory()
                               else None
                               for path in obj.paths}
            result["read"] = obj.permissions['read']
            result["write"] = obj.permissions['write']
            result["remark"] = obj.remark
            result["list_root"] = obj.permissions['list_root']
            result["guest"] = obj.permissions['guest']
            return result
        elif isinstance(obj, SharedFile):
            return {path.get_full_path(): path if path.is_directory() else
                    None for path in obj.paths}
        return json.JSONEncoder.default(self, obj)


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
                targets += parse_targets(line[:-1])
    return targets


def get_targets(target, inputfilename, timeout):
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


def output_files_are_writeable(args):
    for filename in [
        args.outputfilename_xml,
        args.outputfilename_json,
        #  args.outputfilename_normal,
        args.outputfilename_grep,
    ]:
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write('')
            except Exception as e:
                log.exception(e)
                return False
    return True


def save_file(data, filename, dirname):
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    path = os.path.join(dirname, filename)
    if os.path.exists(path):
        count = 1
        while os.path.isfile("%s.%d" % (path, count)):
            count += 1
        path = "%s.%d" % (path, count)

    with open(path, 'wb') as f:
        f.write(data)


def write_xml(output, filename):
    def add_paths_to_node(paths, root):
        for path in paths:
            dir_node = ET.SubElement(root, "directory")
            dir_node.set("name", path.get_full_path())
            if path not in path.paths:
                add_paths_to_node(path.paths, dir_node)

    root = ET.Element("smbcrawler")
    for smbConnection in output.hosts:
        host_node = ET.SubElement(root, "host")
        host_node.set("name", str(smbConnection))
        for share in smbConnection.shares:
            share_node = ET.SubElement(host_node, "share")
            share_node.set("name", str(share))
            share_node.set("remark", share.remark)
            share_node.set("read", str(share.permissions['read']))
            share_node.set("write", str(share.permissions['write']))
            share_node.set("list_root", str(share.permissions['list_root']))
            share_node.set("guest", str(share.permissions['guest']))
            add_paths_to_node(share.paths, share_node)
    tree = ET.ElementTree(root)
    tree.write(filename, encoding='UTF-8', pretty_print=True)


def write_grep(output, filename):
    def write_to_file(smbClient, paths, f):
        for p in paths:
            line = ""
            for s in [str(smbClient),
                      share.name,
                      share.remark,
                      p.get_full_path(),
                      share.get_permissions()]:
                line += s + "\t"
            f.write(line.replace('\n', ' ') + "\n")
            write_to_file(smbClient, p, f)

    with open(filename, "w") as f:
        f.write("host\tshare\tremark\tpath\tpermissions\n")
        for smbClient in output.hosts:
            for share in smbClient.shares:
                if share.paths:
                    write_to_file(smbClient, share.paths, f)
                else:
                    f.write('%s\t%s\t%s\t\t%s\n' % (
                        smbClient,
                        share.name,
                        share.remark,
                        share.get_permissions(),
                    ))


def write_json(output, filename):
    with open(filename, "w") as f:
        json.dump(output, f, cls=MyEncoder, indent=1)


def write_normal(output):
    # TODO
    pass
