import os
import tempfile

from smbcrawler.sql import QueuedDBWriter
from smbcrawler.log import init_logger


class EventReporter(object):
    """
    All events that occurred that should be reported to the user somehow go
    through
    here.
    """

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
        for handler in self.log.handlers:
            if hasattr(handler, "close"):
                handler.close()

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

    def process_target(self, target, port_open=False, instance_name=None):
        self.log.debug("Processing target: %s" % target)
        self.db_queue.write("Target", dict(name=str(target), instance_name=instance_name, port_open=port_open))
        if port_open:
            self.log.info("%s - Connected" % target)
        else:
            self.log.info("%s - No SMB service found" % target)

    def process_share(self, smbclient, target, share):
        self.db_queue.write(
            "Share",
            dict(
                target=str(target),
                name=str(share),
                remark=share.remark,
                auth_access=share.permissions["read"],
                guest_access=share.permissions["guest"],
                write_access=share.permissions["write"],
                read_level=0 if share.permissions["list_root"] else None,
                #  maxed_out=False,
            ),
        )
        self.log.info(
            "%s - Found share: %s [%s]" % (target, share, share.remark)
        )

    def share_finished(self, target, share):
        self.log.info("%s - Share finished: %s" % (target, share))
        self.db_queue.write(
            "Path",
            [target, share, share.paths],
        )

    def process_path(self, target, share, path, size):
        self.db_queue.write(
            "Path", dict(target=target, share=share, name=path, size=size)
        )

    def depth_limit_reached(self, target, share):
        self.log.info(
            " Maximum depth reached: \\\\%s\\%s" % (self.current_target, share)
        )
        self.db_queue.write(
            "Share",
            dict(target=str(target), name=share, maxed_out=False),
            filter_={"name": str(target), "share": share},
        )

    def list_access_denied(self, target):
        self.log.error("%s - Access denied when listing shares" % target)
        self.db_queue.write(
            "Target",
            dict(name=str(target), listable_authenticated=False),
            filter_={"name": str(target)},
        )

    def connection_error(self, target):
        self.log.error("%s - Could not connect" % target)

    def listable_as_user(self, target):
        self.log.success("%s - Can list shares as user" % target)
        self.db_queue.write(
            "Target",
            dict(listable_authenticated=True),
            filter_={"name": str(target)},
        )

    def listable_as_guest(self, target):
        self.log.success("%s - Can list shares as guest" % target)
        self.db_queue.write(
            "Target",
            dict(listable_unauthenticated=True),
            filter_={"name": str(target)},
        )

    def found_guest_access(self, target, share):
        pass

    def found_write_access(self, target, share):
        pass

    def found_secret(self, target, share, path):
        pass

    def found_high_value_file(self, target, share, path):
        pass

    def found_high_value_share(self, target, share):
        pass

    def logon_failure(self, target):
        pass

    def identified_interesting_share(self, target, share):
        self.log.info("\\\\%s\\%s: Crawling with non-default depth" % (target, share))

    def is_boring_share(self, target, share):
        pass

    def downloading_file(self, target, share, path):
        pass

    def skip_share(self, target, share):
        self.db_queue.write(
            "Event",
            {
                "message": "Skipping this share",
                "type": "info",
                "share": self.current_share,
                "target": self.current_target,
            },
        )

        self.log.info(
            "Skipping share %s on target %s..."
            % (
                self.current_share,
                self.current_target,
            )
        )

    def skip_target(self, target, share):
        self.log.info("Skipping target %s..." % self.current_target)

    def skip_directory(self, directory):
        self.log.info("Skip boring directory: %s" % directory)

    def unable_to_delete_test_directory(self, target, share, dirname, exc):
        self.log.error(
            "Unable to delete test directory: \\\\%s\\%s\\%s"
            % (self.smbClient.getRemoteHost(), self, dirname),
            exc_info=exc,
        )
