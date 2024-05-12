import logging
import threading
import queue
import re
import sys

from smbcrawler.shares import SMBShare
from smbcrawler.profiles import find_matching_profile

from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SessionError

PYTEST_ENV = "pytest" in sys.modules

log = logging.getLogger(__name__)


def log_exceptions(silence=""):
    """Catch the exception, log it, and don't reraise it

    `silence` is a regex; if it matches, the exception is silently supressed
     on log levels less than debug.
    """

    def outer_wrapper(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if PYTEST_ENV:
                    raise
                msg = "[%s@%s] %s" % (
                    e.__class__.__name__,
                    func.__name__,
                    str(e),
                )
                if not (silence and re.match(silence, msg)):
                    log.error(msg)
                log.debug(msg, exc_info=True)

        return wrapper

    return outer_wrapper


class CrawlerThread(threading.Thread):
    """Each CrawlerThread crawls one target and reports hosts, shares, paths,
    secrets, etc."""

    def __init__(
        self,
        app,
        login,
        timeout,
        check_write_access=False,
        depth=0,
        crawl_printers_and_pipes=False,
    ):
        self.app = app
        self.login = login
        self.timeout = timeout
        self.check_write_access = check_write_access
        self.depth = depth
        self.crawl_printers_and_pipes = crawl_printers_and_pipes

        self.current_share = None
        self.current_target = None
        self._guest_session = False
        # This if for skipping individual shares/hosts manually
        self._skip_share = False
        self._skip_host = False
        self.killed = False
        self.is_running = False
        self.done = False
        super().__init__()

    def run(self):
        self.is_running = True
        try:
            while not self.killed:
                target = self.app.target_queue.get(block=False)
                self.crawl_host(target)
                with self.app.thread_lock:
                    self.app.targets_finished += 1
        except queue.Empty:
            log.debug("[%s] Queue empty, quitting thread" % self._name)
            self.is_running = False
            self.done = True

    def kill(self):
        self.killed = True

    def check_paused(self):
        self.is_running = False
        self.app.running.wait()
        self.is_running = True

    def skip_share(self):
        self.app.event_reporter.skip_share(self.current_target, self.current_share)
        self._skip_share = True

    def skip_host(self):
        """Stop crawling this host"""
        self.app.event_reporter.skip_host(self.current_target)
        self._skip_host = True

    @log_exceptions()
    def crawl_share(self, share, depth=0):
        self._skip_share = False

        share.check_all_permission(
            self._guest_session,
            self.check_write_access,
        )

        self.app.event_reporter.process_share(
            self.smbClient,
            self.current_target,
            share,
        )

        if depth != 0 and share.permissions["list_root"]:
            self.crawl_dir(share, depth)

        self.app.event_reporter.share_finished(self.current_target, share)

    @log_exceptions(
        silence=".*STATUS_ACCESS_DENIED|STATUS_NOT_SUPPORTED|STATUS_SHARING_VIOLATION.*"
    )
    def crawl_dir(self, share, depth, parent=None):
        if depth == 0:
            self.app.event_reporter.depth_limit_reached(self.current_target, share)
            return

        for f in share.get_dir_list(parent):
            self.check_paused()

            if self._skip_share or self._skip_host or self.killed:
                return

            if f.get_longname() in [".", ".."]:
                continue

            if self._skip_share or self._skip_host or self.killed:
                return

            if parent:
                parent.add_path(f)
            else:
                share.add_path(f)

            if f.is_directory():
                self.process_directory(share, f, depth)
            else:
                self.process_file(share, f)

    @log_exceptions(
        silence=".*STATUS_ACCESS_DENIED|STATUS_NOT_SUPPORTED|STATUS_SHARING_VIOLATION.*"
    )
    def process_file(self, share, f):
        profile = find_matching_profile(
            self.app.profile_collection, "files", f.get_full_path()
        )

        if not profile:
            return

        if profile.get("high_value") is True:
            self.app.event_reporter.found_high_value_file(self.current_target, share, f)

        if profile.get("download") is False or self.app.disable_autodownload:
            return

        def download(data):
            self.app.event_reporter.downloading_file(
                self.current_target,
                share,
                f.get_full_path(),
                data,
            )

        self.smbClient.getFile(
            str(share),
            f.get_full_path(),
            download,
        )

    @log_exceptions()
    def process_directory(self, share, f, depth):
        profile = find_matching_profile(
            self.app.profile_collection, "directories", self.name
        )
        if profile and profile["crawl_depth"]:
            self.app.event_reporter.non_default_depth(str(f))
            depth = profile["depth"]

        self.crawl_dir(share, depth - 1, parent=f)

    @log_exceptions()
    def crawl_host(self, target):
        self.current_share = None
        self.current_target = target
        self._skip_host = False
        self.check_paused()
        if self.killed:
            return False

        if not target.is_port_open(self.timeout):
            self.app.event_reporter.process_target(target, port_open=False)
            return False

        self.smbClient = SMBConnection(
            "*SMBSERVER" if target.port == 139 else target.host,
            target.host,
            sess_port=target.port,
        )

        if not self.smbClient:
            self.app.event_reporter.connection_error(target)
            return False

        self.app.event_reporter.process_target(target, port_open=True)

        # log on
        try:
            shares = self.list_shares(target, as_guest=True)
            self._guest_session = True
            self.app.event_reporter.listable_as_guest(target)
        except Exception:
            self._guest_session = False
            self.smbClient.close()
            self.smbClient = SMBConnection(
                "*SMBSERVER" if target.port == 139 else target.host,
                target.host,
                sess_port=target.port,
            )
            try:
                shares = self.list_shares(target, as_guest=False)
                self.app.event_reporter.listable_as_user(target)
            except SessionError as e:
                if "STATUS_ACCESS_DENIED" in str(e):
                    self.app.event_reporter.list_access_denied(target)
                    return False
                raise

        for s in shares:
            self.check_paused()
            if self.killed or self._skip_host:
                break
            share_name = self.smbClient.add_share(s)
            self.current_share = share_name
            depth = s.effective_depth(
                self.depth,
                self.crawl_printers_and_pipes,
            )
            if depth != self.depth:
                self.app.event_reporter.identified_interesting_share(
                    self.current_target, share_name
                )
            self.crawl_share(s, depth=depth)

        self.smbClient.close()

        return True

    def list_shares(self, target, as_guest=False):
        self.authenticate(target, as_guest=as_guest)

        shares = [
            SMBShare(
                self.smbClient,
                s,
                self.app,
            )
            for s in self.smbClient.listShares()
        ]

        if self.killed or self._skip_host:
            return []

        return shares

    def authenticate(self, target, as_guest=False):
        try:
            if not self.app.credentials_confirmed:
                self.app.cred_lock.acquire()
            if self.killed:
                return
            if as_guest:
                username = ""
                password = ""
            else:
                username = self.login.username or ""
                password = self.login.password or ""
            self.smbClient.login(
                username,
                password,
                domain=self.login.domain,
                lmhash=self.login.lmhash,
                nthash=self.login.nthash,
            )
            if not as_guest:
                self.app.confirm_credentials()
        except SessionError as e:
            if "STATUS_LOGON_FAILURE" in str(e) and not as_guest:
                self.app.report_logon_failure(target)
                self._skip_host = True
            elif "STATUS_LOGON_TYPE_NOT_GRANTED" in str(e):
                # We have no permission to this share, no big deal
                self._skip_host = True
            else:
                raise
        finally:
            if self.app.cred_lock.locked():
                self.app.cred_lock.release()
