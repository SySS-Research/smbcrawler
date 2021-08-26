import multiprocessing
import threading
import sys
import logging

from multiprocessing.dummy import Pool as ThreadPool

import smbcrawler.monkeypatch  # noqa monkeypatch impacket scripts
from smbcrawler.io import get_targets, output_files_are_writeable, \
        DataCollector
from smbcrawler.scanner import CrawlerThread
from smbcrawler.args import parse_args
from smbcrawler.log import init_log

from impacket.smbconnection import SessionError

log = None


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


class ThreadManager(object):
    """Manages the crawler threads

    :global_manager: A multiprocessing.Manager object to manage shared
        variables
    :total_targets: The number of total targets
    :kill_app: callback function taking no arguments that communicates to
        the parent app that we want to quit
    """

    def __init__(self, global_manager, total_targets, kill_app, is_domain,
                 force):
        self.total_targets = total_targets
        self.kill_app = kill_app
        self.is_domain = is_domain
        self.force = force
        self.threads = []
        self.shared_vars = global_manager.dict()
        self.shared_vars['scanned'] = 0
        self.shared_vars['unpaused_threads'] = 0
        self.shared_vars['credentials_confirmed'] = False
        self.all_paused = global_manager.Event()
        self.running = global_manager.Event()
        self.running.set()

    def pause(self):
        print("Pausing threads... be patient")
        self.running.clear()
        self.all_paused.wait()
        print("Threads paused. ", end='')
        self.print_progress()
        print("\ts <n>\tSkip share in thread <n>")
        print("\tk <n>\tKill thread <n> and proceed with next target")
        print("\tr\tResume crawler")
        print("\tq\tWrite output files and quit")
        print("Threads:")
        for i, t in enumerate(self.threads):
            host = t.target.host
            print("\t%d) \\\\%s\\%s" % (
                i, host, t.current_share or "",
            ))
        self.show_menu()

    def show_menu(self):
        cmd = ""
        commands = {
            'k': self.kill_thread,
            's': self.skip_share,
            'q': self.quit,
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

    def skip_share(self, n=None):
        if not n:
            log.error("Missing argument")
            return False
        try:
            self.threads[int(n)].skip_share()
        except (IndexError, ValueError):
            log.error("Invalid argument: %s" % n)
            return False
        self.resume()
        return True

    def kill_thread(self, n=None):
        if not n:
            log.error("Missing argument")
            return False
        try:
            self.threads[int(n)].kill()
        except (IndexError, ValueError):
            log.error("Invalid argument: %s" % n)
            return False
        self.resume()
        return True

    def quit(self):
        for i, t in enumerate(self.threads):
            t.kill()
        self.kill_app()
        self.resume(msg="Quitting...")
        return True

    def resume(self, msg="Resuming..."):
        print(msg)
        self.all_paused.clear()
        self.running.set()
        return True

    def check_paused(self, thread):
        if not self.running.is_set():
            self.shared_vars['unpaused_threads'] -= 1
            if self.shared_vars['unpaused_threads'] == 0:
                self.all_paused.set()
            self.running.wait()
            self.shared_vars['unpaused_threads'] += 1

    def add(self, thread):
        self.threads.append(thread)
        self.shared_vars['unpaused_threads'] += 1

    def remove(self, thread):
        self.threads.remove(thread)
        self.shared_vars['scanned'] += 1
        self.shared_vars['unpaused_threads'] -= 1

    def print_progress(self):
        message = ""
        if self.total_targets > 0:
            scanned = self.shared_vars['scanned']
            message = "Processed %d out of %d hosts (%.2f%%)" % (
                scanned,
                self.total_targets,
                100.*scanned/self.total_targets,
            )
        print(message)

    def report_logon_failure(self, target):
        if (
            not self.shared_vars['credentials_confirmed']
            and not self.force
            and self.is_domain
        ):
            log.fatal("%s:%d - Logon failure; "
                      "aborting to prevent account lockout; "
                      "consider using --force to continue anyway"
                      % (target.host, target.port))
            self.quit()
        else:
            log.warning("%s:%d - Logon failure" % (target.host, target.port))

    def confirm_credentials(self):
        self.shared_vars['credentials_confirmed'] = True


class CrawlerApp(object):
    def __init__(self, global_manager, args):
        self.args = args
        self.sanity_check()
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

        self.output = DataCollector(self.args)
        self.thread_manager = ThreadManager(
            global_manager,
            len(self.targets),
            self.kill,
            self.args.domain not in ['', '.'],
            self.args.force,
        )

        self.killed = False

    def kill(self):
        self.killed = True

    def sanity_check(self):
        if not self.args.target and not self.args.inputfilename:
            log.critical("You must supply a target or an input filename "
                         "(or both)")
            exit(1)
        if not output_files_are_writeable(self.args):
            log.critical("Aborting because output file could not be written. "
                         "This is just going to waste everybody's time.")
            exit(1)
        if not self.args.no_output and all(x is None for x in [
            self.args.outputfilename_xml,
            self.args.outputfilename_json,
            self.args.outputfilename_log,
            self.args.outputfilename_grep,
        ]):
            log.critical("Aborting because not output file name was given. "
                         "This is just going to waste everybody's time. "
                         "Use the -oN parameter to proceed anyway.")
            exit(1)

    def run(self):
        t = threading.Thread(target=self.input_thread)
        t.setDaemon(True)
        t.start()

        pool = ThreadPool(self.args.threads)  # Number of threads
        try:
            pool.map(self.worker, self.targets)
        except Exception as e:
            log.exception(e)
            log.fatal("Exception caught, trying to write output...")
        except KeyboardInterrupt:
            log.info("CTRL-C caught, "
                     "trying to exit gracefully and write output...")
            self.thread_manager.quit()
            pass
        self.output.write_output()
        sys.exit(0)

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
                self.thread_manager.pause()
            if key == " ":
                self.thread_manager.print_progress()

    def worker(self, target):
        if self.killed:
            return
        thread = CrawlerThread(target, self.thread_manager, self.output,
                               self.login, self.args)
        self.thread_manager.add(thread)
        try:
            thread.run()
        except Exception as e:
            if (isinstance(e, SessionError) and
                    'STATUS_LOGON_FAILURE' in str(e)):
                self.thread_manager.report_logon_failure(target)
            else:
                if log.level == logging.DEBUG:
                    log.exception(e)
                else:
                    log.error(e)
        self.thread_manager.remove(thread)


def main(args=None):
    parsed_args = parse_args(args)
    init_log(parsed_args)
    global log
    log = logging.getLogger(__name__)
    cmd_args = ' '.join(args or sys.argv[1:])
    log.info("Starting up with these arguments: " + cmd_args)
    global_manager = multiprocessing.Manager()
    CrawlerApp(global_manager, parsed_args).run()
