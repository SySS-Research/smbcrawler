# Monkey-patch impacket's objects

from impacket import smbconnection
from impacket import smb


class MySMBConnection(smbconnection.SMBConnection, object):
    def __init__(self, *args, **kwargs):
        self.shares = []
        super(MySMBConnection, self).__init__(*args, **kwargs)

    def __iter__(self):
        return iter(self.shares)

    def __str__(self):
        return self.getServerName()

    def add_share(self, share):
        if share not in self.shares:
            self.shares.append(share)
        return str(share)


class MySharedFile(smb.SharedFile, object):
    def __init__(self, *args, **kwargs):
        super(MySharedFile, self).__init__(*args, **kwargs)
        self.paths = []
        self.parent = None
        self.size = self._SharedFile__filesize
        self.high_value = False
        self.content_hash = None

    def __str__(self):
        return self.get_longname()

    def __iter__(self):
        return iter(self.paths)

    def add_path(self, path):
        path.parent = self
        self.paths.append(path)

    def get_full_path(self):
        if self.parent:
            smbpwd = smbconnection.ntpath.join(
                self.parent.get_full_path(), self.get_longname()
            )
            smbpwd = smbconnection.ntpath.normpath(smbpwd)
            return smbpwd
        return self.get_longname()


smb.SharedFile = MySharedFile
smbconnection.SMBConnection = MySMBConnection
