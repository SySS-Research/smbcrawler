import socket
import string
import random
import logging

from smbcrawler.lists import get_regex

from impacket.smbconnection import ntpath

log = logging.getLogger(__name__)


class Target(object):
    def __init__(self, host, timeout):
        if ':' in host:
            self.host, self.port = host.split(':')
            self.port = int(self.port)
        else:
            self.host = host
            self.port = 445
        self.timeout = timeout

    def port_open(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, port))
            s.close()
        except Exception as e:
            log.debug("%s:%d - %s" % (self.host, port, e))
            s.close()
            return False
        log.info("%s:%d - Port open" % (self.host, port))
        return True

    def __str__(self):
        return '%s:%s' % (self.host, self.port)


def normalize_pwd(pwd):
    if pwd:
        smbpwd = ntpath.join(pwd.get_full_path(), '*')
    else:
        smbpwd = ntpath.join("", '*')
        smbpwd = ntpath.normpath(smbpwd)
    return smbpwd


class SMBShare(object):
    def __init__(self, smbClient, share):
        self.smbClient = smbClient
        self.name = share["shi1_netname"][:-1]
        self.remark = share["shi1_remark"][:-1]
        self.is_print_queue = share["shi1_type"] % 0x80000000 == 1
        self.is_device = share["shi1_type"] % 0x80000000 == 2
        self.is_ipc_pipe = share["shi1_type"] % 0x80000000 == 3
        self.is_hidden = share["shi1_type"] & 0x80000000 > 0
        #  https://www.samba.org/samba/docs/Samba-Developers-Guide.pdf
        #  Note: see cifsrap2.txt section5, page 10.
        #  0 for shi1 type indicates a Disk.
        #  1 for shi1 type indicates a Print Queue.
        #  2 for shi1 type indicates a Device.
        #  3 for shi1 type indicates an IPC pipe.
        #  0x8000 0000 (top bit set in shi1 type) indicates a hidden share.
        self.paths = []

        self.permissions = {
            #  'guest_access': False,
            'read': False,
            'write': False,
            'list_root': False,
            'guest': False,
        }

    def __str__(self):
        return self.name

    def __iter__(self):
        return iter(self.paths)

    def add_path(self, path):
        path.parent = None
        self.paths.append(path)

    def get_permissions(self):
        result = "ACCESS DENIED"
        if self.permissions['read']:
            result = "READ"
        if self.permissions['list_root']:
            result = "READ, LIST_ROOT"
        if self.permissions['write']:
            result += ", WRITE"
        if self.permissions['guest']:
            result += ", GUEST"
        return result

    def get_dir_list(self, pwd):
        smbpwd = normalize_pwd(pwd)
        dir_list = self.smbClient.listPath(self.name, smbpwd)
        return dir_list

    def check_all_permission(self, guest, check_write_access):
        if guest:
            self.permissions['guest'] = True
        self.check_permission_read()
        if self.permissions['read']:
            self.check_permission_list()
            if check_write_access:
                self.check_permission_write()

    def check_permission_read(self):
        # check read access by connecting tree
        try:
            tree_id = self.smbClient.connectTree(self.name)
            self.smbClient.disconnectTree(tree_id)
            self.permissions['read'] = True
        except Exception as e:
            log.debug(e)

    def check_permission_write(self):
        """Create an empty directory and delete it right after."""

        distribution = (string.ascii_letters + string.digits)
        dirname = "smbcrawler_DELETEME_" + ''.join(random.choice(distribution)
                                                   for _ in range(8))
        try:
            self.smbClient.createDirectory(str(self), dirname)
            self.permissions['write'] = True
            log.debug("%s is writable" % self)
        except Exception:
            log.debug("%s is readonly" % self, exc_info=True)
            return

        try:
            self.smbClient.deleteDirectory(str(self), dirname)
        except Exception:
            log.error("Unable to delete test directory: %s/%s"
                      % (self, dirname))

    def check_permission_list(self):
        try:
            self.get_dir_list(None)
            self.permissions['list_root'] = True
            log.debug("%s is listable" % self)
        except Exception:
            log.debug("%s is not listable" % self, exc_info=True)

    def effective_depth(self, depth, crawl_printers_and_pipes):
        """Determine depth at which we want to scan this share"""
        if get_regex('interesting_shares').match(str(self)):
            return -1
        elif get_regex('boring_shares').match(str(self)):
            return 0
        elif (self.is_ipc_pipe or self.is_print_queue):
            if crawl_printers_and_pipes:
                return depth
            else:
                return 0
        else:
            return depth
