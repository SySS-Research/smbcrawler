import os
import logging
import tempfile

import peewee
import magic

from smbcrawler.sql import QueuedDBWriter, DbLinkPaths, DbInsert, DbUpdate
from smbcrawler.log import init_db_logger
from smbcrawler.io import get_hash, convert, find_secrets


log = logging.getLogger(__name__)


class EventReporter(object):
    """
    All events that occurred that should be reported to the user somehow go
    through
    here.
    """

    def __init__(self, db_instance, profile_collection):
        self.profile_collection = profile_collection
        self.db_instance = db_instance
        self.db_queue = QueuedDBWriter(db_instance)
        self.fifo_pipe = None
        self.mkfifo()
        try:
            init_db_logger(self.db_queue)
        except Exception:
            self.db_queue.close()
            raise

    def close(self):
        self.db_queue.close()
        for handler in log.handlers:
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
            log("Failed to create FIFO: %s" % e)
        self.fifo_pipe = filename

    def process_target(self, target, port_open=False, instance_name=None):
        log.info("Processing target: %s" % target)
        self.db_queue.write(
            DbInsert(
                "Target",
                dict(
                    name=str(target), instance_name=instance_name, port_open=port_open
                ),
            )
        )
        if port_open:
            log.info("Connected", extra=dict(target=target))
        else:
            log.info("No SMB service found", extra=dict(target=target))

    def process_share(self, smbclient, target, share):
        self.db_queue.write(
            DbInsert(
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
        )

        log.info(
            "Found share [%s]" % share.remark, extra=dict(taget=target, share=share)
        )

        if share.permissions["write"]:
            self.found_write_access(target, share)

        if share.permissions["guest"]:
            self.found_guest_access(target, share)

    def share_finished(self, target, share):
        log.info("Share finished: %s", extra=dict(target=target, share=share))
        self.db_queue.write(DbLinkPaths(target, share, share.paths))

    def process_path(self, target, share, path, size):
        self.db_queue.write(
            DbInsert("Path", dict(target=target, share=share, name=path, size=size))
        )

    def depth_limit_reached(self, target, share):
        log.info("Maximum depth reached: \\\\%s\\%s" % (target, share))
        self.db_queue.write(
            DbUpdate(
                "Share",
                dict(target=str(target), name=share, maxed_out=False),
                filter_={"target": str(target), "name": share},
            )
        )

    def list_access_denied(self, target):
        log.info("%s - Access denied when listing shares" % target)
        self.db_queue.write(
            DbUpdate(
                "Target",
                dict(name=str(target), listable_authenticated=False),
                filter_={"name": str(target)},
            )
        )

    def connection_error(self, target):
        log.error("[\\\\%s\\] Could not connect" % target)

    def listable_as_user(self, target):
        self.db_queue.write(
            DbUpdate(
                "Target",
                dict(listable_authenticated=True),
                filter_={"name": str(target)},
            )
        )

    def listable_as_guest(self, target):
        log.success("Can list shares as guest", extra=dict(target=target))
        self.db_queue.write(
            DbUpdate(
                "Target",
                dict(listable_unauthenticated=True),
                filter_={"name": str(target)},
            )
        )

    def found_guest_access(self, target, share):
        log.success(
            "Found share with listable root directory as guest",
            extra=dict(
                target=target,
                share=share,
            ),
        )

    def found_write_access(self, target, share):
        log.success(
            "Found share with write access in root directory",
            extra=dict(
                target=target,
                share=share,
            ),
        )

    def found_secret(self, target, share, path, secret, content):
        log.success(
            "Found potential secret: %s" % secret["secret"],
            extra=dict(
                target=target,
                share=share,
                path=path,
            ),
        )

        self.db_queue.write(DbInsert("Secret", {"content": content, **secret}))

    def found_high_value_file(self, target, share, path):
        log.success("Found high value file", extra=dict(target=target, share=share))

    def found_high_value_share(self, target, share):
        pass

    def logon_failure(self, target):
        pass

    def non_default_depth(self, target, share):
        log.info(
            "Crawling with non-default depth", extra=dict(target=target, share=share)
        )

    def downloading_file(self, target, share, path, data):
        content_hash = get_hash(data)

        try:
            row = self.db_instance.models["FileContents"].get(content_hash=content_hash)
        except peewee.DoesNotExist:
            mime = magic.from_buffer(data, mime=True)
            file_type = magic.from_buffer(data)

            clean_content = convert(data, mime, file_type)
            secrets = find_secrets(
                clean_content, path, content_hash, self.profile_collection["secrets"]
            )

            if clean_content.encode() == data:
                clean_content = None

            row = self.db_instance.models["FileContents"].create(
                content_hash=content_hash,
                content=data,
                clean_content=clean_content,
            )

            for s in secrets:
                self.found_secret(target, share, path, s, row)

        # Write data to disk
        dirname = self.db_instance.path + ".d"
        os.makedirs(dirname, exist_ok=True)
        path = os.path.join(dirname, content_hash)
        with open(path, "wb") as f:
            f.write(data)

    def skip_share(self, target, share):
        log.info(
            "Skipping share ...",
            extra=dict(
                share=self.current_share,
                target=self.current_target,
            ),
        )

    def skip_target(self, target, share):
        log.info("Skipping target", extra=dict(target=self.current_target))

    def skip_directory(self, target, share, path):
        log.info(
            "Skipping directory", extra=dict(target=target, share=share, path=path)
        )

    def unable_to_delete_test_directory(self, target, share, path, exc):
        log.error(
            "Unable to delete test directory",
            extra=dict(target=target, share=share, path=path),
            exc_info=exc,
        )
