import re
import logging

log = logging.getLogger(__name__)


LISTS = dict(
    interesting_filenames=[
        (".*cred(s|ential).*",),
        (".*secret.*",),
        (".*settings.*",),
        (".*config.*",),
        (".*login.*",),
        (".*bitlocker.*",),
        (".*passw.*",),
        (".*zug(a|ä|ae)ng.*",),
        (".*\\.cfg",),
        (".*\\.ini",),
        (".*\\.config",),
        (".*\\.properties",),
        (".*\\.json",),
        (".*\\.ps1",),
        (".*\\.cmd",),
        (".*\\.bat",),
        (".*\\.bek", "Bitlocker key"),
        (".*\\.key",),
        (".*\\.pem",),
        (".*\\.p7b",),
        (".*\\.p7c",),
        (".*\\.pfx",),
        (".*\\.p12",),
        (".*\\.key",),
        (".*\\.aws",),
        (".*\\.rdp",),
        (".*\\.remmina",),
        (".*\\.exports",),
        (".*\\.kdbx", "Keepass 2.x - Encrypted passwords"),
        (".*\\.kdb", "Keepass 1.x - Encrypted passwords"),
        (".*\\.ppk", "putty private keys"),
        (".*\\.psafe3", "password safe"),
        (".*\\.cscfg", "Cloud config"),
        (".*\\.kix", "KiXtart Script"),
        (".*\\.kwallet", "kde wallet manager"),
        (".*\\.tblk", "VPN profiles"),
        (".*\\.ovpn", "VPN profiles"),
        ("tomcat-users\\.xml", "Apache Tomcat - Plain text passwords"),
        ("AgentConfig\\.xml", "Matrix42 Empirum - Obfuscated passwords"),
        ("NiCfg.*\\.ncp", "Ivanti DSM - Obfuscated passwords"),
        (
            "nhstconf\\.ndb",
            "Netop Remote Control - Encrypted passwords with static key",
        ),
        ("avwin\\.ini", "Avira"),
        ("iconnlocal\\.cfg", "Sophos - Obfuscated passwords"),
        ("SiteList\\.xml", "McAfee - Obfuscated passwords"),
        ("ServerSiteList\\.xml", "McAfee - Obfuscated passwords"),
        ("TrackIt.*\\.xml", "BMC Track IT! - Encrypted passwords with static key"),
        ("unattend.*\\.xml", "Windows installation files - Plain text passwords"),
        ("\\.bash_history", "Bash History - Plain text passwords"),
        ("\\.zsh_history", "Zsh History - Plain text passwords"),
        ("\\.sh_history", "Sh History - Plain text passwords"),
        ("\\.mysql_history", "Mysql History - Plain text passwords"),
        ("shadow", "Unix - Encrypted passwords"),
        ("logins\\.json", "Firefox - Encrypted passwords"),
        ("key3\\.db", "Firefox - Key for logins.json"),
        ("Login Data", "Chrome - Encrypted passwords"),
        (".*\\.bds", "Baramundi Scripts"),
        ("filezilla.xml",),
        ("recentservers.xml",),
        ("terraform.tfvars",),
        ("id_rsa", "private key"),
        ("id_dsa", "private key"),
        ("id_ecdsa", "private key"),
        ("id_ed25519", "private key"),
        ("NTDS.DIT", "User database"),
        ("SAM", "User database"),
        ("SYSTEM", "User database"),
        ("SECURITY", "User database"),
        ("pwd.db",),
        ("secring\\.gpg", "GnuPG - Encrypted private keys"),
    ],
    boring_filenames=[
        (".*\\.dll", "Very unlikely to contain passwords"),
        (".*\\.exe", "Very unlikely to contain passwords"),
        (".*\\.css", "Very unlikely to contain passwords"),
        (".*\\.msi", "Very unlikely to contain passwords"),
    ],
    interesting_shares=[],
    boring_shares=[
        (r"print\$", "Probably only contains drivers"),
        (r"wsus.*|sccm.*|sms.*|msscvm.*|.*reminst.*", "Contains only binary packages"),
        (r"WinSxS", "Backups of binaries"),
        (r"backup", "Backups of binaries"),
    ],
    interesting_directories=[],
    boring_directories=[
        (r"WinSxS", "Backups of binaries"),
    ],
)

REGEXES = {}


def init_list(override, append):
    """Convert the list of strings to compiled regular expressions"""
    global REGEXES
    REGEXES = LISTS.copy()
    for lst in [override, append]:
        for val in lst:
            if ":" not in val:
                log.error("Argument must contain a colon: %s" % val)
                continue
            name = val.split(":")[0]
            if name not in LISTS:
                log.error("Invalid list name: %s" % name)
                continue
            result = re.sub("[^:]+:", "", val)
            if lst == override:
                REGEXES[name].clear()
                REGEXES[name].append((result,))
            else:
                REGEXES[name].append((result,))

    for k, v in REGEXES.items():
        v = [x[0] for x in v]
        v = "|".join(v)
        v = "^" + v + "$"
        v = re.compile(v, flags=re.IGNORECASE)
        REGEXES[k] = v


def get_regex(name):
    return re.compile("")
    return REGEXES[name]
