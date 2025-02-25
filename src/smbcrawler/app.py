import sys
import logging
import queue
import readline  # noqa
import threading
import os
import time

import smbcrawler.monkeypatch  # noqa monkeypatch impacket scripts
from smbcrawler.io import get_targets
from smbcrawler.sql import init_db
from smbcrawler.crawl import CrawlerThread
from smbcrawler.reporter import EventReporter


log = logging.getLogger(__name__)


class Login(object):
    def __init__(self, username, domain, password="", hash=""):
        self.username = username
        self.domain = domain
        self.password = password
        self.hash = hash

    def __str__(self):
        return f"{self.domain}/{self.username}:{self.password or self.hash}"


class CrawlerApp(object):
    """This object manages threads and interactive user input"""

    def __init__(
        self,
        login=None,
        targets=[],
        crawl_file="smbcrawler.crwl",
        threads=1,
        timeout=5,
        depth=0,
        check_write_access=False,
        crawl_printers_and_pipes=False,
        disable_autodownload=False,
        max_file_size=1024 * 200,
        profile_collection=None,
        force=False,
        inputfilename=None,
        cmd=None,
    ):
        self.crawl_file = crawl_file
        # Create output dir
        self.crawl_dir = str(self.crawl_file) + ".d"
        self.content_dir = os.path.join(self.crawl_dir, "content")
        os.makedirs(self.crawl_dir, exist_ok=True)
        os.makedirs(self.content_dir, exist_ok=True)

        self.targets = get_targets(
            targets,
            inputfilename,
        )

        if login:
            self.login = login
        else:
            self.login = Login(" ", "", "")  # guest
        self.max_threads = threads
        self.timeout = timeout
        self.depth = depth
        self.check_write_access = check_write_access
        self.crawl_printers_and_pipes = crawl_printers_and_pipes
        self.max_file_size = max_file_size
        self.disable_autodownload = disable_autodownload
        self.force = force
        self.cmd = cmd

        self.profile_collection = profile_collection

        self.credentials_confirmed = False

        self.target_queue = queue.Queue()
        self.targets_finished = 0
        self.running = threading.Event()

        # Used for modifying class vars
        self.thread_lock = threading.Lock()

        # Used for first credential check
        self.cred_lock = threading.Lock()

    def dry_run(self):
        print("* Effective profile collection:\n%s" % self.profile_collection)
        print("* Targets:\n" + "\n".join(" - %s" % t for t in self.targets))
        print("* Credentials:\n - %s" % self.login)

    def run(self):
        # Instantiate DB
        self.db_instance = init_db(self.crawl_file, cmd=self.cmd)
        self.event_reporter = EventReporter(self.db_instance, self.profile_collection)

        print(
            "Hit <space> for progress, <s> for a status update, and <p> for pause to skip shares or hosts"
        )

        try:
            self._run()
        except Exception as e:
            log.debug(e, exc_info=True)
            log.critical("Exception caught, trying to exit gracefully...")
        except KeyboardInterrupt:
            print("CTRL-C caught, trying to kill threads and exit gracefully...")
            try:
                self.kill_threads()
            except (Exception, KeyboardInterrupt) as e:
                log.debug(e, exc_info=True)
                log.error("Exception during thread killing")
        print("Finishing ...")
        self.event_reporter.close()
        print("Done. Use `smbcrawler report` to analyze results.")

    def pause(self):
        # Use print because log level might not be high enough
        print("Pausing threads... be patient.")
        self.running.clear()
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
        print("\tr\tResume crawler")
        print("\tq\tWrite output files and quit")
        print("Threads:")
        for i, t in enumerate(self.threads):
            if t.done:
                continue
            print(
                "\t%d) \\\\%s\\%s"
                % (
                    i,
                    t.current_target.host,
                    t.current_share or "",
                )
            )

        cmd = ""
        commands = {
            "h": self.skip_host,
            "s": self.skip_share,
            "q": self.kill_threads,
            # Leave this an undocumented feature
            "r": self.resume,
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

    def skip_share(self, n=None):
        if not n:
            log.error("Missing argument")
            return False
        try:
            for N in n.split(","):
                self.threads[int(N)].skip_share()
        except (IndexError, ValueError):
            log.error("Invalid argument: %s" % n)
            return False
        print("Skipping shares: %s; resuming" % n)
        self.resume()
        return True

    def skip_host(self, n=None):
        if not n:
            log.error("Missing argument")
            return False
        try:
            for N in n.split(","):
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
            try:
                t.join()
            except Exception as e:
                if "cannot join current thread" not in str(e):
                    log.error(f"Error while joining thread: {e}")
        return True

    def resume(self, msg="Resuming..."):
        log.info(msg)
        print(msg)
        self.running.set()
        return True

    def print_status(self):
        message = "Current threads:\n"
        for i, t in enumerate(self.threads):
            if t.done:
                continue
            message += f"{i}) \\\\{t.current_target}\\"
            if t.current_share:
                message += f"{t.current_share}\\"
                if t.current_share.current_path:
                    message += str(t.current_share.current_path)
            message += "\n"

        print(message)

    def print_progress(self):
        message = ""
        scanned = self.targets_finished
        targets = len(self.targets)
        message = "Processed %d out of %d hosts (%.2f%%)" % (
            scanned,
            targets,
            100.0 * scanned / targets,
        )
        print(message)

    def report_logon_failure(self, target):
        if not self.credentials_confirmed and not self.force:
            log.critical(
                "[%s] Logon failure; "
                "aborting to prevent account lockout; "
                "consider using the 'force' flag to continue anyway" % target
            )
            self.cred_lock.release()
            self.kill_threads()
        else:
            log.warning("[%s] Logon failure" % target)

    def confirm_credentials(self):
        self.credentials_confirmed = True

    def _run(self):
        for target in self.targets:
            self.target_queue.put(target)
        self.threads = []
        for t in range(self.max_threads):
            thread = CrawlerThread(
                self,
                self.login,
                self.timeout,
                check_write_access=self.check_write_access,
                depth=self.depth,
                crawl_printers_and_pipes=self.crawl_printers_and_pipes,
            )
            thread.start()
            self.threads.append(thread)
        self.running.set()

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
        import io

        try:
            while True:
                key = self.read_key()
                if key == "p":
                    self.pause()
                elif key == "s":
                    self.print_status()
                elif key == " ":
                    self.print_progress()
        except io.UnsupportedOperation:
            log.warning("stdin is pseudofile, cannot read keys")
