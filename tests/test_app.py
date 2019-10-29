#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from difflib import unified_diff
import json
import os
import shutil
import subprocess
import sys
import time
import re
import xml.etree.ElementTree as ET
import logging

import pytest

# Not sure why, but it's needed so the filestream log is filled
logging.getLogger('smbcrawler').setLevel(logging.DEBUG)

# https://stackoverflow.com/a/33515264/1308830
SCRIPT_DIR = os.path.dirname(__file__)
sys.path.append(os.path.join(SCRIPT_DIR, 'helpers'))
import smbd_config  # noqa

TMP = '/tmp/smbcrawler_test'
ROOT_DIR = os.path.join(TMP, 'root')
OUTPUT = os.path.join(TMP, 'output')
SMBD_PATH = '/usr/sbin/smbd'
SMBPASSWD_PATH = '/usr/bin/smbpasswd'
HOST = '127.0.0.1'
PORT = 1445

TREE = {
    'level1': {
        'level2': {
            'fileA': None,
        },
        'fileB': None,
    },
}

FILES = {
    'public': TREE,
    'public_ro': TREE,
    'private': TREE,
    'home': TREE,
    'guest': TREE,
    'fileC': None,
}

TESTS = {
    'standard_run': [
        f'127.0.0.1:{PORT}',
        '-u', 'testcrawler',
        '-p', 'crawlerpass',
        '-D', '-1',
        '-w',
        '-vv',
    ],
    'skip_share': [
        f'127.0.0.1:{PORT}',
        '-u', 'testcrawler',
        '-p', 'crawlerpass',
        '-D', '-1',
        '-aO', 'boring_shares:GuestSh.*',
        '-w',
        '-vv',
    ],
    'download_file': [
        f'127.0.0.1:{PORT}',
        '-u', 'testcrawler',
        '-p', 'crawlerpass',
        '-D', '-1',
        '-aO', 'interesting_filenames:.*ileA',
        '-w',
        '-vv',
    ],
}


def create_fs(parent, content):
    for name, val in content.items():
        if isinstance(val, dict):
            create_dir(parent, name, val)
        else:
            create_file(parent, name)


def create_dir(parent, dirname, content={}):
    path = os.path.join(parent, dirname)
    os.mkdir(path)
    create_fs(path, content)
    if dirname == 'public':
        os.chmod(path, 0o777)


def create_file(parent, name):
    path = os.path.join(parent, name)
    with open(path, 'w') as f:
        f.write(name)


def run_smb_server(configfile):
    proc = subprocess.Popen(
        [
            SMBD_PATH,
            '--configfile', configfile,
            '--foreground',
        ]
    )
    return proc


def create_config(path, **kwargs):
    content = smbd_config.CONFIG % kwargs
    with open(path, 'w') as f:
        f.write(content)


@pytest.fixture(scope="session")
def smb_server():
    configfile = os.path.join(TMP, 'smbd.conf')
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(ROOT_DIR)
    create_fs(ROOT_DIR, FILES)
    create_config(
        configfile,
        ROOT=ROOT_DIR,
        PORT=PORT,
    )
    global proc
    proc = run_smb_server(configfile)
    time.sleep(1)
    yield HOST, PORT
    os.kill(proc.pid, 15)


def test_smbd(smb_server):
    process = subprocess.Popen(['ss', '-ntl'],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = process.communicate()
    assert '%s:%d' % (HOST, PORT) in out.decode()


def run_smbcrawler(smb_server, args):
    host, port = smb_server
    try:
        from smbcrawler.app import main
        main(args)
    except SystemExit as e:
        assert e.code == 0


@pytest.fixture(scope="session")
def output(smb_server):
    host, port = smb_server
    args = TESTS['standard_run'] + ['-oA', OUTPUT]
    run_smbcrawler(smb_server, args)

    result = {}
    for frmt in ['log', 'grep', 'json']:
        with open(OUTPUT + '.%s' % frmt, 'r') as f:
            result[frmt] = f.read()
    result['json'] = json.loads(result['json'])
    result['xml'] = ET.parse(OUTPUT + '.xml')

    yield result


def test_grep(output):
    grep = output['grep']
    lines = grep.split('\n')
    assert lines[0] == 'host\tshare\tremark\tpath\tpermissions'
    print_share = None
    guest_share = None
    private_share = None
    public_share = None
    for line in lines:
        if 'print$' in line:
            print_share = line.split('\t')
        if 'GuestShare' in line:
            guest_share = line.split('\t')
        if 'private' in line:
            private_share = line.split('\t')
        if 'public\t' in line:
            public_share = line.split('\t')
    assert print_share
    assert guest_share
    assert private_share
    assert print_share[1] == 'print$'
    assert print_share[2] == 'Printer Drivers'
    assert guest_share[1] == 'GuestShare'
    assert guest_share[2] == 'This is a guest share'
    assert guest_share[4] == 'READ, LIST_ROOT, GUEST'
    assert private_share[4] == 'ACCESS DENIED, GUEST'
    assert public_share[4] == 'READ, LIST_ROOT, WRITE, GUEST'


def test_xml(output):
    xml = output['xml']
    print_node = xml.find('./host/share[@name="print$"]')
    assert print_node.attrib['remark'] == 'Printer Drivers'
    assert print_node.attrib['read'] == 'False'
    assert print_node.attrib['list_root'] == 'False'
    assert print_node.attrib['guest'] == 'True'

    guest_node = xml.find('./host/share[@name="GuestShare"]')
    assert guest_node.attrib['remark'] == 'This is a guest share'
    assert guest_node.attrib['read'] == 'True'
    assert guest_node.attrib['list_root'] == 'True'
    assert guest_node.attrib['guest'] == 'True'

    public_node = xml.find('./host/share[@name="public"]')
    assert public_node.attrib['write'] == 'True'

    dir_nodes = public_node.findall('.//directory')
    assert dir_nodes[0].attrib['name'] == 'level1'
    assert dir_nodes[1].attrib['name'] == 'level1\\level2'
    assert dir_nodes[2].attrib['name'] == 'level1\\level2\\fileA'


def test_json(output):
    jsn = output['json']
    shares = list(jsn.values())
    for k, v in shares[0].items():
        if k == 'print$':
            print_share = v
        if k == 'GuestShare':
            guest_share = v
        if k == 'public':
            public_share = v
        if k == 'public_ro':
            public_ro_share = v
    assert public_share['write']
    assert not public_ro_share['write']
    assert not print_share['read']
    assert print_share['remark'] == 'Printer Drivers'
    assert not print_share['list_root']
    assert print_share['guest']
    assert guest_share['read']
    assert guest_share['remark'] == 'This is a guest share'
    assert guest_share['list_root']
    assert guest_share['guest']


def test_log(output):
    strings = [
        ('I', "Found share: GuestShare [This is a guest share] "
         "READ, LIST_ROOT, GUEST"),
    ]
    for record in output['log'].splitlines():
        assert not record.startswith('E')
        assert not record.startswith('C')
        for s in strings:
            if record.startswith(s[0]) and record.strip().endswith(s[1]):
                strings.remove(s)
    assert strings == []


def scan_dir(dir):
    subfolders, files = [], []

    for f in os.scandir(dir):
        if f.is_dir():
            subfolders.append(f.path)
        if f.is_file():
            files.append(f.path)

    for dir in list(subfolders):
        sf, f = scan_dir(dir)
        subfolders.extend(sf)
        files.extend(f)
    return subfolders, files


def get_diff(output_dir, data_dir):
    """Checks if the output matches pre-recorded output, minus timestamps"""
    subfolders, files = scan_dir(data_dir)
    result = ""
    for f in files:
        f1 = os.path.join(output_dir, f[len(data_dir)+1:])
        f2 = os.path.join(data_dir, f[len(data_dir)+1:])
        with open(f1, 'r') as fd:
            buff1 = fd.read()
        with open(f2, 'r') as fd:
            buff2 = fd.read()
        if f.endswith('.log'):
            continue  # dont check logs for now. too much variation.
            # Remove timestamps, debug statements and line numbers
            re1 = r'^(.) [0-9 :-]{19} '
            buff1 = re.sub(re1, r'\1 ', buff1, flags=re.MULTILINE)
            buff2 = re.sub(re1, r'\1 ', buff2, flags=re.MULTILINE)
            re2 = r'^(. .*.py):[0-9]* '
            buff1 = re.sub(re2, r'\1 ', buff1, flags=re.MULTILINE)
            buff2 = re.sub(re2, r'\1 ', buff2, flags=re.MULTILINE)

            # https://stackoverflow.com/questions/54992433
            LinePattern = r'^D .*'
            ListPattern = "(Line\n)+(Line$)?|(\nLine$)|(^Line$)"
            Pattern = re.sub("Line", LinePattern, ListPattern)
            buff1 = re.sub(Pattern, r'', buff1)
            buff2 = re.sub(Pattern, r'', buff2)

        diff = unified_diff(buff1.splitlines(), buff2.splitlines())
        result += '\n'.join(diff)
    return result


@pytest.fixture(params=TESTS.keys())
def testcase(request):
    return request.param


def test_args(smb_server, testcase):
    host, port = smb_server
    args = TESTS[testcase]
    data_dir = testcase
    OUT_DIR = os.path.join(TMP, 'output', data_dir)
    shutil.rmtree(OUT_DIR, ignore_errors=True)
    os.makedirs(OUT_DIR)
    args += ['-oA', os.path.join(OUT_DIR, 'output')]
    run_smbcrawler(smb_server, args)
    DATA_DIR = os.path.join(SCRIPT_DIR, 'data', data_dir)
    assert get_diff(OUT_DIR, DATA_DIR) == ""
