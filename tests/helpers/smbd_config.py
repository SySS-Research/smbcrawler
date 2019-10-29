CONFIG = """
[global]
    workgroup = TESTGROUP
    interfaces = lo 127.0.0.0/8
    bind interfaces only = yes
    enable core files = false
    smb ports = %(PORT)d
    log level = 2
    map to guest = Bad User
    passdb backend = smbpasswd
    smb passwd file = %(ROOT)s/smbpasswd
    log file = %(ROOT)s/samba.log
    lock directory = %(ROOT)s/samba
    state directory = %(ROOT)s/samba
    cache directory = %(ROOT)s/samba
    pid directory = %(ROOT)s/samba
    private dir = %(ROOT)s/samba
    ncalrpc dir = %(ROOT)s/samba
    usershare allow guests = yes
[public]
    path = %(ROOT)s/public
    guest ok = yes
    read only = no
    writeable = yes
    browseable = yes
    public = yes
    create mask = 0666
    directory mask = 0777
[public_ro]
    path = %(ROOT)s/public_ro
    guest ok = yes
    read only = yes
[private]
    path = %(ROOT)s/private
    read only = no
[homes]
   comment = Home Directories
   browseable = no
   read only = yes
   create mask = 0700
   directory mask = 0700
   path = %(ROOT)s/home
[GuestShare]
  comment = This is a guest share
  path = %(ROOT)s/guest
  read only = no
  guest ok = yes
[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
"""
