# SmbCrawler

SmbCrawler is no-nonsense tool that takes credentials and a list of
hosts and 'crawls' (or 'spiders') through those shares. Features:

- takes host names, IP addresses, IP ranges, or an nmap xml file as
  input
- checks permissions (check for 'write' permissions is opt-in, because
  it requires creating an empty directory on the share)
- crawling depth is customizable
- outputs results in machine-readable formats or as an interactive HTML
  report
- pass-the-hash support
- auto-download interesting files
- report potential secrets
- threaded
- pausable
- interactively skip single shares and hosts

## Installation

If you require instructions on how to install a Python package, I
recommend you make sure you [have `pipx`
installed](https://pipx.pypa.io/stable/installation/) and run
`pipx install smbcrawler`.

SmbCrawler can automatically convert some binary files like PDF, XLSX,
DOCX, ZIP, etc. to plain text using
[MarkItDown](https://github.com/microsoft/markitdown). Because this
package is pulling a lot of dependencies, it is marked as an extra.
However, it is highly recommended to get the best results. If you want
to automatically convert binaries, install SmbCrawler like this:

``` console
pipx install 'smbcrawler[binary-conversion]'
```

Adding shell completion is highly recommended. As a Python app using the
`click` library, you can add tab completion to bash, zsh and fish using
the [usual
mechanism](https://click.palletsprojects.com/en/8.1.x/shell-completion/#enabling-completion).

## Example

Run it like this (10 threads, maximum depth 5):

    $ smbcrawler crawl -i hosts.txt -u pen.tester -p iluvb0b -d contoso.local -t 10 -D 5

## Major changes in version 1.0

SmbCrawler has undergone a major overhaul. The most significant changes
are:

- We cleaned up the CLI and introduced a "profile" mechanism to steer
  the behavior of the crawler
- The output is now a sqlite database instead of scattered JSON files
- Permissions are now reported more granularly

The old CLI arguments regarding "interesting files", "boring shares" and
so on was clunky and confusing. Instead we now use "profiles; see below
for details.

Also, I realized I basically reinvented relational databases, except did
so very poorly, so why not use sqlite directly? The sqlite approach
enables us to produce a nice interactive HTML report with good
performance. You can still export results in various formats if you need
to use the data in some tool pipeline.

The old way SmbCrawler reported permissions sometimes wasn't very
useful. For example, it's not uncommon that you have read permissions in
the root directory of the share, but all sub directories are protected,
e.g. for user profiles. SmbCrawler will now report how deep it was able
to read the directory tree of a share and whether it maxed out or could
have gone deeper if you had supplied a higher value for the maximum
depth argument.

If you prefer the old version, it's still available on PyPI and
installable with `pipx install smbcrawler==0.2.0`, for example.

## Usage

During run time, you can use the following keys:

- `p`: pause the crawler and skip single hosts or shares
- `<space>`: print the current progress
- `s`: print a more detailed status update

For more information, run `smbcrawler -h`.

## Notes

Even in medium sized networks, SmbCrawler will find tons of data. The
challenge is to reduce false positives.

### Notes on permissions

It's important to realize that permissions can apply on the service
level and on the file system level. The remote SMB service may allow you
to authenticate and your user account may have read permissions in
principle, but it could lack these permissions on the file system.

SmbCrawler will report if you have permissions to:

- authenticate against a target as guest and list shares
- authenticate against a target with the user creds
- access a share as guest
- access a share with the user creds
- create a directory in the share's root directory
- the deepest directory level of a share that could be accessed (limited
  by the `--depth` argument)

Because it is non-trivial to check permissions of SMB shares without
attempting the action in question, SmbCrawler will attempt to create a
directory on each share. Its name is
`smbcrawler_DELETEME_<8 random characters>` and will be deleted
immediately, but be aware anyway.

> [!WARNING]
> Sometimes you have the permission to create directories, but not to
> delete them, so you will leave an empty directory there.

### Profiles

To decide what to do with certain shares, files or directories,
SmbCrawler has a feature called "profiles". Take a look at the [default
profile](https://github.com/SySS-Research/smbcrawler/blob/main/src/smbcrawler/default_profile.yml).

Profiles are loaded from files with extensions `*.yml` or `*.yaml` from
these locations:

- The built-in default profile
- `$XDG_DATA_HOME/smbcrawler/` (`~/.local/share/smbcrawler` by default)
- The extra directory defined by `--extra-profile-directory`
- The extra files defined by `--extra-profile-file`

Profiles from each location override previous definitions.

The `regex` value defines whether a profile matches, and the last
matching profile will be used. All regular expressions are
case-insensitive, mirroring the most common behavior in the Windows
world.

Since it can be confusing how profiles from different sources work
together, make sure to make use of the `--dry-run` parameter. It shows
you the effective configuration and does nothing more.

Let's look at each section, which is always a list of dictionaries. Each
of the keys of the dictionary is an arbitrary label and each of the
values is again a dictionary with different properties.

#### Files

- `comment`: A helpful string describing this profile
- `regex`: A regular expression that defines which files this profile
  applies to. The *last* regex that matches is the one that counts.
- `regex_flags`: An array of flags which will be passed to the regex
  [`match` function](https://docs.python.org/3/library/re.html#flags)
- `high_value` (default: `false`): If a file is "high value", its
  presence will be reported, but it will not necessarily be downloaded
  (think virtual hard drives - important, but too large to download
  automatically)
- `download` (default: `true`): If `true`, the first 200KiBi will be
  downloaded (or the entire file if `high_value=true`) and parsed for
  secrets

#### Shares and directories

- `comment`, `regex`, `regex_flags`: Same as above
- `high_value`: its presence will be reported and crawl depth changed to
  infinity
- `crawl_depth`: Crawl this share or directory up to a different depth
  than what is defined by the `--depth` argument

#### Secrets

- `comment`, `regex_flags`: Same as above
- `regex`: A regular expression matching the secret. The secret itself
  can be a named group with the name `secret`.

### Typical workflow

It makes sense to first run SmbCrawler with crawling depth 1 to get an
idea of what you're dealing with. In this first run, you can enable the
write check with `-w`:

    $ smbcrawler -C permissions_check.crwl crawl -D1 -t10 -w \
        -i <INPUT FILE> -u <USER> -d <DOMAIN> -p <PASSWORD>

Note that this checks for write and read premissions in the root
directory of each share only. Only a full run will tell you more about
how deep the read permissions go.

After the initial permissions check, you can identify interesting and
boring shares for your next run or several runs. Some shares like
`SYSVOL` and `NETLOGON` appear many times, so you should set the crawl
depth to zero on your next run and pick one host to scan these duplicate
shares in a third run. Here is an example:

    $ smbcrawler -C dc_only.crwl crawl -D -1 <DC IP> \
        -u <USER> -d <DOMAIN> -p <PASSWORD>
    $ smbcrawler -C full.crwl crawl -D5 -t10 -i <NEW INPUT FILE> \
        -u <USER> -d <DOMAIN> -p <PASSWORD> \
        --extra-profile-file skip_sysvol.yml

Here, `skip_sysvol.yml` would be:

``` yaml
shares:
  sysvol:
    comment: "Skip sysvol and netlogon share"
    regex: 'SYSVOL|NETLOGON'
    crawl_depth: 0
```

Feel free to include other shares here which you may think are not worth
crawling.

### Output

The raw data is contained in an SQLite database and a directory
(`output.crwl` and `output.crwl.d` by default). The directory contains
two more directories: one with the downloaded files unique-ified by the
hash content and a directory mirroring all shares with symlinks pointing
to the content files. The latter is good for grepping through all
downloaded files.

The data can be transformed to various formats. You can also simply
access the database with `sqlitebrowser`, for example. Some useful views
have been pre-defined. Or you can output JSON and use `jq` to mangle the
data.

If you want to display all shares that you were able to read beyond the
root directory in a LaTeX table, for instance, use this query:

``` sql
SELECT target_id || " & " || name || " & " || remark || " \\"
FROM share
WHERE read_level > 0
ORDER BY target_id, name
```

There is also an experimental HTML output feature. It may not be
entirely useful yet for large amounts of data.

### Help out

If you notice a lot of false positives or false negatives in the
reported secrets, please help out and let me know. Community input is
important when trying to improve automatic detection. Best case
scenario: provide a pull request with changes to the default profile
file.

## Credits

Adrian Vollmer, SySS GmbH

## License

MIT License; see `LICENSE` for details.
