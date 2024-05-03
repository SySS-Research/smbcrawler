import os
import tempfile

from smbcrawler.sql import QueuedDBWriter
from smbcrawler.log import init_logger


class EventReporter(object):
    def __init__(self, db_instance):
        self.db_queue = QueuedDBWriter(db_instance)
        self.fifo_pipe = None
        self.mkfifo()
        try:
            self.log = init_logger(self.db_queue, self.fifo_pipe, id_=id(self))
        except Exception:
            self.db_queue.close()
            raise

    def close(self):
        self.db_queue.close()
        try:
            os.unlink(self.fifo_pipe)
        except Exception:
            pass
        try:
            os.rmdir(self._tmpdir)
        except Exception:
            pass

    def mkfifo(self):
        tmpdir = tempfile.mkdtemp(prefix="smbcrawler_")
        self._tmpdir = tmpdir
        filename = os.path.join(tmpdir, "fifo_pipe")
        try:
            os.mkfifo(filename)
        except OSError as e:
            self.log("Failed to create FIFO: %s" % e)
        self.fifo_pipe = filename

    def process_host(self, host):
        self.log.debug("Processing host: %s" % host)
        self.db_queue.write("Host", dict(name=host))

    def process_share(self, smbclient, host, share, remark, permissions):
        self.db_queue.write(
            "Share",
            dict(
                host=host.host,
                name=share,
                remark=remark,
                auth_access="ACCESS DENIED" not in permissions,
                guest_access="GUEST" in permissions,
                write_access="WRITE" in permissions,
                #  read_level = peewee.IntegerField(default=-1, null=True)
                #  maxed_out=False,
            ),
        )
        #  self.log.info(
        #      "%s:%d - Found share: %s [%s] %s"
        #      % (
        #          self.smbClient._remoteHost,
        #          self.smbClient._sess_port,
        #          share,
        #          share.remark,
        #          share.get_permissions(),
        #      )
        #  )

    def process_path(self, host, share, path, size):
        self.db_queue.write("Path", dict(host=host, share=share, name=path, size=size))
        #  self.log.info(
        #      "\\\\%s\\%s\\%s [%d]"
        #      % (
        #          self.smbClient,
        #          share,
        #          f.get_full_path(),
        #          f.size,
        #      )
        #  )

    def found_guest_access(self, host, share):
        pass

    def found_write_access(self, host, share):
        pass

    def found_secret(self, host, share, path):
        pass

    def found_high_value_file(self, host, share, path):
        pass

    def found_high_value_share(self, host, share):
        pass

    def logon_failure(self, host):
        pass

    def is_interesting_share(self, host, share):
        pass

    def is_boring_share(self, host, share):
        pass

    def downloading_file(self, host, share, path):
        pass

    def skip_share(self, host, share):
        self.db_queue.write(
            "event",
            {
                "message": "Skipping this share",
                "type": "info",
                "share": self.current_share,
                "host": self.current_target,
            },
        )

        self.log.info(
            "[%s] Skipping share %s on host %s..."
            % (
                self._name,
                self.current_share,
                self.current_target,
            )
        )

    def skip_host(self, host, share):
        self.log.info(
            "[%s] Skipping host %s..."
            % (
                self._name,
                self.current_target,
            )
        )

    def skip_directory(self, directory):
        self.log.info("Skip boring directory: %s" % directory)

    def unable_to_delete_test_directory(self, host, share):
        pass
