import os
import logging
import tempfile

from smbcrawler.sql import QueuedDBWriter, DbLinkPaths, DbInsert, DbUpdate
from smbcrawler.log import init_db_logger
from smbcrawler.io import convert, find_secrets, create_link


log = logging.getLogger(__name__)


class EventReporter(object):
    """
    All events that occurred that should be reported to the user somehow go
    through here.
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

    def process_target(self, target, port_open=False):
        log.info("Processing target: %s" % target)
        self.db_queue.write(
            DbInsert(
                "Target",
                dict(
                    name=str(target),
                    port_open=port_open,
                ),
            )
        )
        if port_open:
            log.info("Connected", extra=dict(target=target))
        else:
            log.info("No SMB service found", extra=dict(target=target))

    def update_target(self, target, netbios_name):
        self.db_queue.write(
            DbUpdate(
                "Target",
                dict(netbios_name=netbios_name),
                filter_=dict(name=str(target)),
            )
        )

    def found_share(self, target, share):
        name = str(share)
        if name.endswith(":445"):
            name = name[:-4]
        self.db_queue.write(
            DbInsert(
                "Share",
                dict(
                    target=str(target),
                    name=name,
                    remark=share.remark,
                    #  maxed_out=False,
                ),
            )
        )

        log.info(
            "Found share: %s" % share.remark, extra=dict(taget=target, share=share)
        )

        if share.permissions["write"]:
            self.found_write_access(target, share)

    def share_finished(self, target, share):
        log.info("Share finished", extra=dict(target=target, share=share))
        self.db_queue.write(DbLinkPaths("Path", {}, target, share, share.paths))
        read_level = max(share.read_level or [0]) - min(share.read_level or [0])
        if share.maxed_out is None and share.read_level:
            maxed_out = True
        else:
            maxed_out = False

        self.db_queue.write(
            DbUpdate(
                "Share",
                dict(
                    read_level=read_level,
                    maxed_out=maxed_out,
                ),
                filter_={"target": str(target), "name": share.name},
            )
        )

    def depth_limit_reached(self, target, share):
        log.info("Maximum depth reached: \\\\%s\\%s" % (target, share))
        self.db_queue.write(
            DbUpdate(
                "Share",
                dict(target=str(target), name=share, maxed_out=False),
                filter_={"target": str(target), "name": share.name},
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

    def update_share_permissions(self, target, share):
        guest_access = share.permissions["guest"] and share.permissions["list_root"]
        self.db_queue.write(
            DbUpdate(
                "Share",
                dict(
                    guest_access=guest_access,
                    auth_access=share.permissions["read"],
                    write_access=share.permissions["write"],
                    read_level=0 if share.permissions["list_root"] else None,
                ),
                filter_=dict(target=str(target), name=str(share)),
            )
        )
        if guest_access:
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

    def found_secret(self, target, share, path, secret, content_hash):
        # Reduce number of false positives
        if len(secret) < 3:
            return

        log.success(
            f"Found potential secret ({secret.get('comment')}): {secret['secret']}",
            extra=dict(
                target=target,
                share=share,
                path=path,
            ),
        )

        self.db_queue.write(
            DbInsert("Secret", {"content_hash": content_hash, **secret})
        )

    def found_high_value_file(self, target, share, path, profile):
        if profile.get("download", True):
            verb = "Found"
        else:
            verb = "Seen"
        comment = profile.get("comment")
        msg = f"{verb} high value file"
        if comment:
            msg += f" ({comment})"
        log.success(msg, extra=dict(target=target, share=share, path=path))

    def found_high_value_directory(self, target, share, path, profile):
        comment = profile.get("comment")
        msg = "Found high value directory"
        if comment:
            msg += f" ({comment})"
        log.success(msg, extra=dict(target=target, share=share))

    def found_high_value_share(self, target, share):
        log.success(
            "Found readable high value share", extra=dict(target=target, share=share)
        )
        self.db_queue.write(
            DbUpdate(
                "Share",
                dict(high_value=True),
                filter_=dict(target=str(target), name=str(share)),
            )
        )

    def logon_failure(self, target):
        log.info("Logon failure", extra=dict(target=target))

    def non_default_depth(self, target, share):
        log.info(
            "Crawling with non-default depth", extra=dict(target=target, share=share)
        )

    def downloaded_file(self, target, share, path, local_path, content_hash, tree):
        log.info("Downloaded", extra=dict(target=target, share=share, path=path))

        new_filename = os.path.join(os.path.dirname(local_path), content_hash)
        create_link(str(target), str(share), path, new_filename, tree)

        if os.path.exists(new_filename):
            # File already seen, discard
            os.unlink(local_path)
            return

        os.rename(local_path, new_filename)

        clean_content = None
        try:
            clean_content = convert(new_filename)
        except Exception:
            log.debug(
                "Unable to parse",
                exc_info=True,
                extra=dict(target=target, share=share, path=path),
            )
            return

        with open(new_filename, "rb") as fp:
            old_content = fp.read()
        if clean_content and clean_content.encode() != old_content:
            with open(new_filename + ".txt", "w") as fp:
                fp.write(clean_content)

        secrets = find_secrets(clean_content, self.profile_collection["secrets"])

        for s in secrets:
            self.found_secret(target, share, path, s, content_hash)

    def skip_share(self, target, share):
        log.info(
            "Skipping share ...",
            extra=dict(
                share=str(share),
                target=str(target),
            ),
        )

    def skip_target(self, target):
        log.info("Skipping target", extra=dict(target=target))

    def skip_directory(self, target, share, path):
        log.info(
            "Skipping directory", extra=dict(target=target, share=share, path=path)
        )

    def unable_to_delete_test_directory(self, target, share, path, exc):
        log.error(
            "Unable to delete test directory",
            extra=dict(target=target, share=share, path=path),
        )
