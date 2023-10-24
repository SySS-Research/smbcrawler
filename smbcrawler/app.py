import sys
import os
import logging
import queue
import re
import threading
import time

import smbcrawler.monkeypatch  # noqa monkeypatch impacket scripts
from smbcrawler.io import get_targets, save_file, write_files, write_secrets, \
        to_grep_line
from smbcrawler.shares import SMBShare
from smbcrawler.lists import get_regex

from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SessionError

log = logging.getLogger(__name__)
sharegrep_log = logging.getLogger('sharegrep_logger')
pathgrep_log = logging.getLogger('pathgrep_logger')


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


class Login(object):
    def __init__(self, username, domain, password="", hash=""):
        self.username = username
        self.domain = domain
        self.password = password

        try:
            self.lmhash = hash.split(':')[0]
            self.nthash = hash.split(':')[1]
        except (IndexError, AttributeError):
            self.nthash = ""
            self.lmhash = ""


class CrawlerApp(object):
    def __init__(self, args, cmd=None):
        self.args = args
        self.cmd = cmd

        self.targets = get_targets(
            self.args.target,
            self.args.inputfilename,
            self.args.timeout,
        )

        self.login = Login(
            self.args.user,
            self.args.domain,
            password=self.args.password,
            hash=self.args.hash,
        )

        self.credentials_confirmed = False
        self.autodownload_dir = os.path.join(
            self.args.output_dir,
            self.args.session_name + "_autodownload",
        )
        self.secrets_filename = os.path.join(
            self.args.output_dir,
            self.args.session_name + "_secrets.json",
        )
        self.files_filename = os.path.join(
            self.args.output_dir,
            self.args.session_name + "_files.json",
        )

    def run(self):
        log.info("Starting up with these arguments: " + self.cmd)

        try:
            self._run()
        except Exception as e:
            log.exception(e)
            log.critical("Exception caught, trying to exit gracefully...")
        except KeyboardInterrupt:
            msg = (
                "CTRL-C caught, trying to kill threads "
                "and exit gracefully..."
            )
            print(msg)
            log.info(msg)
            try:
                self.kill_threads()
            except (Exception, KeyboardInterrupt) as e:
                log.error("Exception during thread killing")
                log.debug(e, exc_info=True)
        log.info("Writing output...")
        print("Writing output...")
        write_files(self.files_filename)
        write_secrets(self.secrets_filename)
        sys.exit(0)

    def pause(self):
        # Use print because log level might not be high enough
        print("Pausing threads... be patient.")
        CrawlerThread.running.clear()
        while True:
            time.sleep(1)
            count = sum(t.is_running for t in self.threads)
            print("Pausing... %d threads still running" % count)
            if count == 0:
                break

        print("Threads paused.")
        self.print_progress()
        self.show_menu()

    def show_menu(self):
        print("\ts <n>[,<m>,...]\tSkip share in thread <n>")
        print("\th <n>[,<m>,...]\tSkip host in thread <n>")
        print("\td <n>\tShow debug info of thread <n>")
        print("\tr\tResume crawler")
        print("\tq\tWrite output files and quit")
        print("Threads:")
        for i, t in enumerate(self.threads):
            if t.done:
                continue
            print("\t%d) \\\\%s\\%s" % (
                i, t.current_target.host, t.current_share or "",
            ))

        cmd = ""
        commands = {
            'h': self.skip_host,
            's': self.skip_share,
            'q': self.kill_threads,
            #  'd': self.show_debug_info,
            # Leave this an undocumented feature
            'r': self.resume,
        }
        while True:
            cmd = input("> ")
            arg = None
            if " " in cmd:
                cmd, arg = cmd.split()[:2]
            if cmd in commands.keys():
                if arg:
                    if commands[cmd](arg):
                        break
                else:
                    if commands[cmd]():
                        break
            else:
                print("Unkown command: %s" % cmd)

    def show_debug_info(self, n=None):
        if not n:
            log.error("Missing argument")
            return False
        print(self.threads[int(n)].__dict__)

    def skip_share(self, n=None):
        if not n:
            log.error("Missing argument")
            return False
        try:
            for N in n.split(','):
                self.threads[int(N)].skip_share()
        except (IndexError, ValueError):
            log.error("Invalid argument: %s" % n)
            return False
        print("Skipped shares: %s; resuming" % n)
        self.resume()
        return True

    def skip_host(self, n=None):
        if not n:
            log.error("Missing argument")
            return False
        try:
            for N in n.split(','):
                self.threads[int(N)].skip_host()
        except (IndexError, ValueError):
            log.error("Invalid argument: %s" % n)
            return False
        print("Skipped hosts: %s; resuming" % n)
        self.resume()
        return True

    def kill_threads(self):
        for t in self.threads:
            t.kill()
        self.resume(msg="Killing threads...")
        for t in self.threads:
            t.join()
        return True

    def resume(self, msg="Resuming..."):
        log.info(msg)
        CrawlerThread.running.set()
        return True

    def print_progress(self):
        message = ""
        scanned = CrawlerThread.targets_finished
        targets = len(self.targets)
        message = "Processed %d out of %d hosts (%.2f%%)" % (
            scanned,
            targets,
            100.*scanned/targets,
        )
        print(message)

    def report_logon_failure(self, target):
        if not self.credentials_confirmed and not self.args.force:
            log.critical("%s:%d - Logon failure; "
                         "aborting to prevent account lockout; "
                         "consider using the 'force' flag to continue anyway"
                         % (target.host, target.port))
            self.kill_threads()
        else:
            log.warning("%s:%d - Logon failure" % (target.host, target.port))

    def confirm_credentials(self):
        self.credentials_confirmed = True

    def _run(self):
        for target in self.targets:
            CrawlerThread.target_queue.put(target)
        CrawlerThread.app = self
        self.threads = []
        for t in range(self.args.threads):
            thread = CrawlerThread(
                self.login,
                check_write_access=self.args.check_write_access,
                depth=self.args.depth,
                crawl_printers_and_pipes=self.args.crawl_printers_and_pipes,
            )
            thread.start()
            self.threads.append(thread)
        CrawlerThread.running.set()

        t = threading.Thread(target=self.input_thread)
        t.setDaemon(True)
        t.start()

        # Wait for threads to finish
        for t in self.threads:
            t.join()

    def read_key(self):
        import termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] &= ~(termios.ICANON | termios.ECHO)  # c_lflags
        c = None
        try:
            termios.tcsetattr(fd, termios.TCSANOW, new)
            c = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, old)
        return c

    def input_thread(self):
        """Runs in a separate thread and only registers key events"""

        while True:
            key = self.read_key()
            if key == "p":
                self.pause()
            if key == " ":
                self.print_progress()


class CrawlerThread(threading.Thread):
    target_queue = queue.Queue()
    targets_finished = 0
    running = threading.Event()

    # Used for modifying class vars
    thread_lock = threading.Lock()

    # Used for first credential check
    cred_lock = threading.Lock()

    def __init__(self, login, check_write_access=False, depth=0,
                 crawl_printers_and_pipes=False):
        self.login = login
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
                target = self.target_queue.get(block=False)
                self.crawl_host(target)
                with CrawlerThread.thread_lock:
                    CrawlerThread.targets_finished += 1
        except queue.Empty:
            log.debug("[%s] Queue empty, quitting thread" %
                      self._name)
            self.is_running = False
            self.done = True

    def kill(self):
        self.killed = True

    def check_paused(self):
        self.is_running = False
        CrawlerThread.running.wait()
        self.is_running = True

    def skip_share(self):
        log.info("[%s] Skipping share %s on host %s..." % (
            self._name,
            self.current_share,
            self.current_target,
        ))
        self._skip_share = True

    def skip_host(self):
        """Stop crawling this host"""
        log.info("[%s] Skipping host %s..." % (
            self._name,
            self.current_target,
        ))
        self._skip_host = True

    @log_exceptions()
    def crawl_share(self, share, depth=0):
        self._skip_share = False

        share.check_all_permission(
            self._guest_session,
            self.check_write_access,
        )

        log.info("%s:%d - Found share: %s [%s] %s"
                 % (self.smbClient._remoteHost,
                    self.smbClient._sess_port,
                    share,
                    share.remark,
                    share.get_permissions(),
                    ))
        sharegrep_log.info(
            to_grep_line(
                [
                    self.smbClient,
                    self.current_target,
                    share,
                    share.remark,
                    share.get_permissions(),
                ]
            )
        )

        if depth == 0 or not share.permissions['list_root']:
            return None

        self.crawl_dir(share, depth)
        return None

    @log_exceptions(
        silence='.*STATUS_ACCESS_DENIED|STATUS_NOT_SUPPORTED|STATUS_SHARING_VIOLATION.*'
    )
    def crawl_dir(self, share, depth, parent=None):
        if depth == 0:
            log.debug("[%s] Maximum depth reached: \\\\%s\\%s\\%s" %
                      (self._name, self.current_target, share, parent))
            return

        for f in share.get_dir_list(parent):
            self.check_paused()

            if (self._skip_share or self._skip_host or self.killed):
                return

            if f.get_longname() in ['.', '..']:
                continue

            if (self._skip_share or self._skip_host or self.killed):
                return

            if parent:
                parent.add_path(f)
            else:
                share.add_path(f)

            # output path info
            log.info('\\\\%s\\%s\\%s [%d]' % (
                self.smbClient,
                share,
                f.get_full_path(),
                f.size,
            ))
            pathgrep_log.info(
                to_grep_line([
                    self.smbClient,
                    share,
                    f.get_full_path(),
                    f.size,
                ])
            )

            if f.is_directory():
                self.process_directory(share, f, depth)
            elif (
                get_regex('interesting_filenames').match(str(f))
                and not get_regex('boring_filenames').match(str(f))
            ):
                self.process_file(share, f)

    @log_exceptions(
        silence='.*STATUS_ACCESS_DENIED|STATUS_NOT_SUPPORTED|STATUS_SHARING_VIOLATION.*'
    )
    def process_file(self, share, f):
        if self.app.args.disable_autodownload:
            return

        def auto_download(data):
            save_file(
                self.app.autodownload_dir,
                data,
                str(self.smbClient),
                str(share),
                f.get_full_path(),
            )

        self.smbClient.getFile(
            str(share),
            f.get_full_path(),
            auto_download,
        )

    @log_exceptions()
    def process_directory(self, share, f, depth):
        if get_regex('boring_directories').match(str(f)):
            log.info("[%s] Skip boring directory: %s" % (self._name, str(f)))
        else:
            self.crawl_dir(
                share,
                depth-1,
                f,
            )

    @log_exceptions()
    def crawl_host(self, target):
        log.debug("[%s] Processing host: %s" % (self._name, target.host))

        self.current_share = None
        self.current_target = target
        self._skip_host = False
        self.check_paused()
        if self.killed:
            return False

        if not target.port_open(target.port):
            log.info("[%s] %s - No SMB service found" % (
                self._name,
                target.host,
            ))
            return False

        self.smbClient = SMBConnection(
            '*SMBSERVER' if target.port == 139 else target.host,
            target.host,
            sess_port=target.port,
        )

        if not self.smbClient:
            log.error("[%s] %s:%d - Could not connect" % (
                self._name,
                target.host,
                target.port,
            ))
            return False

        log.info("[%s] %s:%s - Connected"
                 % (self._name, target.host, target.port))

        # log on
        try:
            shares = self.list_shares(target, as_guest=True)
            self._guest_session = True
        except Exception:
            self._guest_session = False
            self.smbClient.close()
            self.smbClient = SMBConnection(
                '*SMBSERVER' if target.port == 139 else target.host,
                target.host,
                sess_port=target.port,
            )
            try:
                shares = self.list_shares(target, as_guest=False)
            except SessionError as e:
                if 'STATUS_ACCESS_DENIED' in str(e):
                    log.error("[%s] %s:%s - Access denied when listing shares"
                              % (self._name, target.host, target.port))
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
                    "\\\\%s:%d\\%s: Crawling with non-default depth %d" % (
                        target.host,
                        target.port,
                        share_name,
                        depth
                    )
                )
            self.crawl_share(s, depth=depth)

        self.smbClient.close()

        return True

    def list_shares(self, target, as_guest=False):
        self.authenticate(target, as_guest=as_guest)

        shares = [SMBShare(self.smbClient, s)
                  for s in self.smbClient.listShares()]

        if self.killed or self._skip_host:
            return []

        if as_guest:
            log.success("[%s] %s:%s - Guest login succeeded"
                        % (self._name, target.host, target.port))

        return shares

    def authenticate(self, target, as_guest=False):
        try:
            if not self.app.credentials_confirmed:
                CrawlerThread.cred_lock.acquire()
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
                and 'STATUS_LOGON_FAILURE' in str(e)
                and not as_guest
            ):
                self.app.report_logon_failure(target)
                self._skip_host = True
            elif (
                isinstance(e, SessionError)
                and 'STATUS_LOGON_TYPE_NOT_GRANTED' in str(e)
            ):
                # We have no permission to this share, no big deal
                self._skip_host = True
            else:
                raise
        finally:
            if CrawlerThread.cred_lock.locked():
                CrawlerThread.cred_lock.release()
