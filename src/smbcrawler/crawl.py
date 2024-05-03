import logging
import threading
import queue
import re

from smbcrawler.shares import SMBShare
from smbcrawler.lists import get_regex

from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SessionError

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
            share.remark,
            share.get_permissions(),
        )

        if depth == 0 or not share.permissions["list_root"]:
            return None

        self.crawl_dir(share, depth)
        return None

    @log_exceptions(
        silence=".*STATUS_ACCESS_DENIED|STATUS_NOT_SUPPORTED|STATUS_SHARING_VIOLATION.*"
    )
    def crawl_dir(self, share, depth, parent=None):
        if depth == 0:
            log.debug(
                "[%s] Maximum depth reached: \\\\%s\\%s\\%s"
                % (self._name, self.current_target, share, parent)
            )
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

            self.app.event_reporter.process_path(
                self.smbClient, str(share), f.get_full_path(), f.size
            )

            if f.is_directory():
                self.process_directory(share, f, depth)
            elif get_regex("interesting_filenames").match(str(f)) and not get_regex(
                "boring_filenames"
            ).match(str(f)):
                self.process_file(share, f)

    @log_exceptions(
        silence=".*STATUS_ACCESS_DENIED|STATUS_NOT_SUPPORTED|STATUS_SHARING_VIOLATION.*"
    )
    def process_file(self, share, f):
        if self.app.disable_autodownload:
            return

        def auto_download(data):
            pass
            # TODO
            #  save_file(
            #      self.app.autodownload_dir,
            #      data,
            #      str(self.smbClient),
            #      str(share),
            #      f.get_full_path(),
            #  )

        self.smbClient.getFile(
            str(share),
            f.get_full_path(),
            auto_download,
        )

    @log_exceptions()
    def process_directory(self, share, f, depth):
        if get_regex("boring_directories").match(str(f)):
            self.app.event_reporter.skip_directory(str(f))
        else:
            self.crawl_dir(
                share,
                depth - 1,
                f,
            )

    @log_exceptions()
    def crawl_host(self, target):
        self.app.event_reporter.process_host(target)

        self.current_share = None
        self.current_target = target
        self._skip_host = False
        self.check_paused()
        if self.killed:
            return False

        if not target.is_port_open(self.timeout):
            log.info(
                "[%s] %s - No SMB service found"
                % (
                    self._name,
                    target.host,
                )
            )
            return False

        self.smbClient = SMBConnection(
            "*SMBSERVER" if target.port == 139 else target.host,
            target.host,
            sess_port=target.port,
        )

        if not self.smbClient:
            log.error(
                "[%s] %s:%d - Could not connect"
                % (
                    self._name,
                    target.host,
                    target.port,
                )
            )
            return False

        log.info("[%s] %s:%s - Connected" % (self._name, target.host, target.port))

        # log on
        try:
            shares = self.list_shares(target, as_guest=True)
            self._guest_session = True
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
            except SessionError as e:
                if "STATUS_ACCESS_DENIED" in str(e):
                    log.error(
                        "[%s] %s:%s - Access denied when listing shares"
                        % (self._name, target.host, target.port)
                    )
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
                log.info(
                    "\\\\%s:%d\\%s: Crawling with non-default depth %d"
                    % (target.host, target.port, share_name, depth)
                )
            self.crawl_share(s, depth=depth)

        self.smbClient.close()

        return True

    def list_shares(self, target, as_guest=False):
        self.authenticate(target, as_guest=as_guest)

        shares = [SMBShare(self.smbClient, s) for s in self.smbClient.listShares()]

        if self.killed or self._skip_host:
            return []

        if as_guest:
            log.success(
                "[%s] %s:%s - Guest login succeeded"
                % (self._name, target.host, target.port)
            )

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
        except Exception as e:
            if (
                isinstance(e, SessionError)
                and "STATUS_LOGON_FAILURE" in str(e)
                and not as_guest
            ):
                self.app.report_logon_failure(target)
                self._skip_host = True
            elif isinstance(e, SessionError) and "STATUS_LOGON_TYPE_NOT_GRANTED" in str(
                e
            ):
                # We have no permission to this share, no big deal
                self._skip_host = True
            else:
                raise
        finally:
            if self.app.cred_lock.locked():
                self.app.cred_lock.release()
