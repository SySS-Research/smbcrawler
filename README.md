SmbCrawler
==========

SmbCrawler is no-nonsense tool that takes credentials and a list of hosts
and 'crawls' (or 'spiders') through those shares. Features:

* takes host names, IP addresses, IP ranges, or an nmap xml file as input
* checks permissions (check for 'write' permissions is opt-in, because it
  requires creating an empty directory on the share)
* crawling depth is customizable
* threaded
* outputs machine-readable formats
* pass-the-hash support
* auto-download interesting files
* report potential secrets
* pausable
* interactively skips single shares and hosts


Installation
------------

Install with `python3 -m pip install .`. Make sure `$HOME/.local/bin` is in
your `$PATH`.

Alternatively, install dependencies manually and run with `python3 -m smbcrawler`.


Example
-------

Run it like this:

```
$ smbcrawler -i hosts.txt -u pen.tester -p iluvb0b -d contoso.local \
        -t 5 -D 5
```


Usage
-----

During run time, you can use the following keys:

* `p`: pause the crawler and skip single hosts or shares (experimental
  feature, be careful)
* `<space>`: print the current progress

For more information, run `smbcrawler -h`.


Notes
-----

Even in medium sized networks, SmbCrawler will find tons of data. The
challenge is to reduce false positives.

### Notes on permissions

`READ` is not an interesting permission. This means you have read permissions
at the share level, but access can still be restricted at the file system
level. `LIST_ROOT` means you can actually list the root directory of that
share.

In general, the permissions reported by SmbCrawler only apply to the root
directory of a share.

Also, the `WRITE` permission means that you have the permission to create
directories.

Because it is non-trivial to check permissions of SMB shares without
attempting the action in question, SmbCrawler will attempt to create a
directory on each share. Its name is `smbcrawler_DELETEME_<8 random
characters>` and will be deleted immediately, but be aware anyway. Sometimes
you have the permission to create directories, but not to delete them, so
you will leave an empty directory there.

Regarding NULL sessions or guest access, it's a little tricky. Guest access
can happen on a host level, meaning you can list shares, but not actually
access the shares. The file system permissions can also differ between a
guest user and an authenticated user. When SmbCrawler repots a share with
`GUEST` permission, that means you can list the shares of that host as an
unauthenticated user. That's why I recommend running SmbCrawler separately
against these shares without providing any credentials.


### Typical workflow

It makes sense to first run SmbCrawler with crawling depth 0 to get an idea of
what you're dealing with. In this first run, you can enable the write check
with `-w`:

```
$ smbcrawler -D0 -t10 -w -i <INPUT FILE> \
    -u <USER> -d <DOMAIN> -p <PASSWORD> \
    -s permission_check
```

Afterwards, you can identify interesting and boring shares for your next run
or several runs. Some shares like `SYSVOL` and `NETLOGON` appear many times,
so you should declare these as "boring" on your next run and pick one host
to scan these duplicate shares in a third run. Here is an example:

```
$ smbcrawler -D5 -t10 -i <NEW INPUT FILE> \
    -u <USER> -d <DOMAIN> -p <PASSWORD> \
    -aA 'boring_shares:SYSVOL|NETLOGON' \
    -s full_run
$ smbcrawler -D -1 <DC IP> \
    -u <USER> -d <DOMAIN> -p <PASSWORD> \
    -s dc_only
```

As noted above, if there are hosts with `GUEST` permissions, run it again
without credentials:

```
$ smbcrawler -D5 -t10 -i <INPUT FILE WITH GUEST HOSTS> \
    -aA 'boring_shares:SYSVOL|NETLOGON' \
    -s guest_access
```


### Errors

Some errors like `STATUS_ACCESS_DENIED` are not necessarily a problem. It's
normal to encounter directories to which you have no access.

### Output

You can increase or decrease the verbosity with command line arguments, but
it's best to leave it at the default value. To see what's going, run `tail
-f` either on the log file or one of the grep files in another terminal as
needed.

This makes it easier to see the progress when pressing `<space>`.

Output files are machine readable, either in "grep" format or in JSON. For
JSON files, I recommend something like `jless` to access its contents.

### Secrets

SmbCrawler automatically reports obvious secrets, but it's also a good idea
to grep for several keywords (case insensitive) in the autodownload
directory:

* `net use`
* `runas`
* `ConverTo-SecureString`
* `----- PRIVATE KEY`
* `password` in various languages
* ...

Be creative!

A helpful command to get an overview over all secrets is as follows:

```
$ jq  'values[]|.[].secret' fullrun_secrets.json | cut -c -80 | sort -u | less
```

Note that encoding can be an issue. `grep -ir password` will not find
passwords in UTF-16 encoded files, for example. That's why the secret
detection of SmbCrawler attempts to normalize the encoding beforehand. PDFs
are also automatically converted to text. (Office documents are TBD.)

Don't forget about the files itself. These might be interesting:

* `kdbx` (KeePass database)
* `vhdx`, `vhd`, `vmdk` (virtual hard drives)
* CVs, employee reviews, etc.
* ...

If you notice a lot of false positives or false negatives, please help out
and let me know. Community input is important when trying to improve
automatic detection.


Credits
-------

Adrian Vollmer, SySS GmbH


License
-------

MIT License; see `LICENSE` for details.
