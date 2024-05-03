import sys
import logging
import queue
import threading
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

        try:
            self.lmhash = hash.split(":")[0]
            self.nthash = hash.split(":")[1]
        except (IndexError, AttributeError):
            self.nthash = ""
            self.lmhash = ""


class CrawlerApp(object):
    """This object manages threads and interactive user input"""

    def __init__(
        self,
        login,
        targets=[],
        crawl_file="smbcrawler.crwl",
        threads=1,
        timeout=5,
        depth=0,
        check_write_access=False,
        crawl_printers_and_pipes=False,
        disable_autodownload=False,
        force=False,
        inputfilename=None,
        cmd=None,
    ):
        self.cmd = cmd or ""

        self.targets = get_targets(
            targets,
            inputfilename,
        )

        self.login = login
        #  self.login = Login(
        #      self.args.user,
        #      self.args.domain,
        #      password=self.args.password,
        #      hash=self.args.hash,
        #  )
        self.max_threads = threads
        self.timeout = timeout
        self.depth = depth
        self.check_write_access = check_write_access
        self.crawl_printers_and_pipes = crawl_printers_and_pipes
        self.disable_autodownload = disable_autodownload
        self.force = force

        self.credentials_confirmed = False

        self.target_queue = queue.Queue()
        self.targets_finished = 0
        self.running = threading.Event()

        # Used for modifying class vars
        self.thread_lock = threading.Lock()

        # Used for first credential check
        self.cred_lock = threading.Lock()

        # Instantiate DB
        self.db_instance = init_db(crawl_file)
        self.event_reporter = EventReporter(self.db_instance)

    def run(self):
        log.info("Starting up with these arguments: " + self.cmd)

        try:
            self._run()
        except Exception as e:
            log.exception(e)
            log.critical("Exception caught, trying to exit gracefully...")
        except KeyboardInterrupt:
            msg = "CTRL-C caught, trying to kill threads and exit gracefully..."
            print(msg)
            log.info(msg)
            try:
                self.kill_threads()
            except (Exception, KeyboardInterrupt) as e:
                log.error("Exception during thread killing")
                log.debug(e, exc_info=True)
        log.info("Writing output...")
        print("Writing output...")
        self.event_reporter.close()

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
        print("\td <n>\tShow debug info of thread <n>")
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
            #  'd': self.show_debug_info,
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
            for N in n.split(","):
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
            t.join()
        return True

    def resume(self, msg="Resuming..."):
        log.info(msg)
        self.running.set()
        return True

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
                "%s:%d - Logon failure; "
                "aborting to prevent account lockout; "
                "consider using the 'force' flag to continue anyway"
                % (target.host, target.port)
            )
            self.kill_threads()
        else:
            log.warning("%s:%d - Logon failure" % (target.host, target.port))

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
                if key == " ":
                    self.print_progress()
        except io.UnsupportedOperation:
            log.warning("stdin is pseudofile, cannot read keys")
