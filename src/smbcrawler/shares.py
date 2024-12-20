import socket
import string
import random
import logging

from smbcrawler.profiles import find_matching_profile

from impacket.smbconnection import ntpath
import impacket

log = logging.getLogger(__name__)


class Target(object):
    def __init__(self, host):
        if ":" in host:
            self.host, self.port = host.split(":")
            self.port = int(self.port)
        else:
            self.host = host
            self.port = 445

    def is_port_open(self, timeout):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((self.host, self.port))
            s.close()
        except Exception as e:
            log.debug(str(e), extra=dict(target=self))
            s.close()
            return False
        log.info("Port open", extra=dict(target=self))
        return True

    def __str__(self):
        return "%s:%s" % (self.host, self.port)


def normalize_pwd(pwd):
    if pwd:
        smbpwd = ntpath.join(pwd.get_full_path(), "*")
    else:
        smbpwd = ntpath.join("", "*")
        smbpwd = ntpath.normpath(smbpwd)
    return smbpwd


class SMBShare(object):
    def __init__(self, smbClient, target, share, app):
        self.smbClient = smbClient
        self.target = target
        self.name = share["shi1_netname"][:-1]
        self.share = self.name
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
            "read": False,
            "write": False,
            "list_root": False,
            "guest": False,
        }

        self.event_reporter = app.event_reporter
        self.profile_collection = app.profile_collection
        self.current_path = None
        self.read_level = None
        self.maxed_out = None

    def __str__(self):
        return self.name

    def __iter__(self):
        return iter(self.paths)

    def add_path(self, path):
        path.parent = None
        self.paths.append(path)
        self.current_path = path

    def get_dir_list(self, pwd):
        smbpwd = normalize_pwd(pwd)
        dir_list = self.smbClient.listPath(self.name, smbpwd)
        return dir_list

    def check_all_permission(self, guest, check_write_access):
        if guest:
            self.permissions["guest"] = True
        self.check_permission_read()
        if self.permissions["read"]:
            self.check_permission_list()
        if check_write_access:
            self.check_permission_write()
        self.event_reporter.update_share_permissions(self.target, self)

    def check_permission_read(self):
        # check read access by connecting tree
        try:
            tree_id = self.smbClient.connectTree(self.name)
            self.smbClient.disconnectTree(tree_id)
            self.permissions["read"] = True
        except impacket.smbconnection.SessionError as exc:
            log.debug(exc, exc_info=True)

    def check_permission_write(self):
        """Create an empty directory and delete it right after."""

        distribution = string.ascii_letters + string.digits
        dirname = "smbcrawler_DELETEME_" + "".join(
            random.choice(distribution) for _ in range(8)
        )
        try:
            self.smbClient.createDirectory(str(self), dirname)
            self.permissions["write"] = True
            log.debug("%s is writable" % self)
        except (impacket.smb3.SessionError, impacket.smbconnection.SessionError):
            log.debug("%s is readonly" % self, exc_info=False)
            return

        try:
            self.smbClient.deleteDirectory(str(self), dirname)
        except impacket.smb3.SessionError as exc:
            self.event_reporter.unable_to_delete_test_directory(
                self.current_target, self.current_share, dirname, exc
            )

    def check_permission_list(self):
        try:
            self.get_dir_list(None)
            self.permissions["list_root"] = True
            log.debug("%s is listable" % self)
        except impacket.smbconnection.SessionError:
            log.debug("%s is not listable" % self, exc_info=True)

    def effective_depth(self, depth, crawl_printers_and_pipes):
        """Determine depth at which we want to scan this share"""

        profile = find_matching_profile(self.profile_collection, "shares", self.name)

        if profile:
            depth = profile.get("crawl_depth", depth)

        if self.is_ipc_pipe or self.is_print_queue:
            if crawl_printers_and_pipes:
                return depth
            else:
                return 0
        else:
            return depth

    def add_read_level(self, depth):
        """Increase the deepest read level we have seen on this share"""
        if self.read_level is None:
            self.read_level = []
        self.read_level.append(depth)
