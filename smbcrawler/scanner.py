import logging

from smbcrawler.shares import SMBShare
from smbcrawler.lists import get_regex
from smbcrawler.io import save_file

from impacket.smbconnection import SMBConnection

log = logging.getLogger(__name__)


class CrawlerThread(object):
    def __init__(self, target, thread_manager, output, login, args):
        self.target = target
        self.thread_manager = thread_manager
        self.output = output
        self.login = login
        self.args = args
        self.current_share = None
        self.killed = False
        self._guest_session = False
        # This if for skipping individual shares manually, controlled by the
        # thread manager.
        self._skip_share = False

    def run(self):
        self.scan_target()

    def check_paused(self):
        self.thread_manager.check_paused(self)

    def skip_share(self):
        log.info("Skipping share %s on target %s..." % (
            self.current_share,
            self.target.host,
        ))
        self._skip_share = True

    def kill(self):
        """Stop crawling this target and kill the thread"""
        log.debug("Killing thread crawling target %s..." % self.target.host)
        self.killed = True

    def spider_share(self, share, pwd=None, level=0):
        if not pwd:
            share.check_all_permission(
                self._guest_session,
                self.args.check_write_access,
            )

            log.info("%s:%d - Found share: %s [%s] %s"
                     % (self.smbClient._remoteHost,
                        self.smbClient._sess_port,
                        share,
                        share.remark,
                        share.get_permissions(),
                        ))

        if level == 0 or not share.permissions['list_root']:
            return None

        dir_list = share.get_dir_list(pwd)
        for f in dir_list:
            self.check_paused()
            if self.killed or self._skip_share:
                break
            if f.get_longname() not in ['.', '..']:
                if pwd:
                    pwd.add_path(f)
                else:
                    share.add_path(f)
                # output path info
                log.info('\\\\%s\\%s\\%s [%d]' % (
                    self.smbClient,
                    share,
                    f.get_full_path(),
                    f.size,
                ))
                if f.is_directory():
                    if get_regex('boring_directories').match(str(f)):
                        log.info("Skip boring directory: %s" % str(f))
                    else:
                        try:
                            self.spider_share(
                                share,
                                pwd=f,
                                level=level-1,
                            )
                        except Exception as e:
                            if log.level == logging.DEBUG:
                                log.exception(e)
                            else:
                                log.error(e)
                elif (
                    get_regex('interesting_filenames').match(str(f))
                    and not get_regex('boring_filenames').match(str(f))
                ):
                    def auto_download(data):
                        save_file(
                            data,
                            "%s_%s_%s" % (self.smbClient, share, f),
                            self.args.outputdirname
                        )
                    self.smbClient.getFile(
                        str(share),
                        f.get_full_path(),
                        auto_download,
                    )
        return None

    def scan_target(self):
        self.current_share = None
        self.check_paused()
        if self.killed:
            return False

        if not self.target.port_open(self.target.port):
            log.error("%s - No SMB service found" % self.target.host)
            return False

        self.smbClient = SMBConnection(
            '*SMBSERVER' if self.target.port == 139 else self.target.host,
            self.target.host,
            sess_port=self.target.port,
        )

        if not self.smbClient:
            log.error("%s:%d - Could not connect" % (self.target.host,
                                                     self.target.port
                                                     ))
            return False

        log.info("%s:%s - Connected" % (self.target.host, self.target.port))

        if self.smbClient.isLoginRequired():
            self.smbClient.login(
                self.login.username or "",
                self.login.password or "",
                domain=self.login.domain,
                lmhash=self.login.lmhash,
                nthash=self.login.nthash,
            )
            self.thread_manager.confirm_credentials()
        else:
            self.smbClient.login("", "")
        if self.smbClient.isGuestSession():
            self._guest_session = True

        self.output.add_smbhost(self.smbClient)
        shares = [SMBShare(self.smbClient, s)
                  for s in self.smbClient.listShares()]
        for s in shares:
            self.check_paused()
            if self.killed:
                break
            share_name = self.smbClient.add_share(s)
            self.current_share = share_name
            depth = s.effective_depth(
                self.args.spider_depth,
                self.args.crawl_printers_and_pipes,
            )
            if depth != self.args.spider_depth:
                log.info("%s:%d - %s: Crawling with non-default depth %d" % (
                    self.target.host,
                    self.target.port,
                    share_name,
                    depth
                ))
            self.spider_share(s, level=depth)
        self.smbClient.close()
        return True
