import click

from smbcrawler.version import __version__


help_alias = dict(context_settings=dict(help_option_names=["-h", "--help"]))


@click.group(**help_alias)
@click.version_option(__version__)
@click.option(
    "-C",
    "--crawl-file",
    default="output.crwl",
    show_default=True,
    help="path to output file",
)
def cli(crawl_file):
    pass


@click.command(**help_alias)
@click.pass_context
@click.option(
    "-u",
    "--user",
    help="user name, if omitted we'll try a null session",
)
@click.option(
    "-d",
    "--domain",
    default=".",
    show_default=True,
    help="the user's domain",
)
@click.option(
    "-p",
    "--password",
    default="",
    prompt=True,
    hide_input=True,
    help="password [omit for a password prompt]",
)
@click.option(
    "-H",
    "--hash",
    help="NTLM hash, can be used instead of a password",
)
@click.option(
    "-f",
    "--force",
    default=False,
    is_flag=True,
    help="always keep going after STATUS_LOGON_FAILURE occurs",
)
@click.option(
    "-T",
    "--timeout",
    type=int,
    default=5,
    show_default=True,
    help="Timeout in seconds when attempting to connect to an " "SMB service",
)
@click.option(
    "-t",
    "--threads",
    type=int,
    default=1,
    show_default=True,
    help="Number of parallel threads",
)
@click.option(
    "-D",
    "--depth",
    default=1,
    type=int,
    show_default=True,
    help="crawling depth; 0 lists only share names and no directories or "
    "files, -1 lists everything",
)
@click.option(
    "-w",
    "--check-write-access",
    is_flag=True,
    default=False,
    help="Check for write access;"
    " WARNING: This creates and deletes a directory in the share's"
    " root directory. If you know a better method, let me know.",
)
@click.option(
    "-A",
    "--disable-autodownload",
    is_flag=True,
    default=False,
    help="Don't download any files",
)
@click.option(
    "-Y",
    "--extra-profile-directory",
    multiple=True,
    help="Path to a directory containing extra profiles in the form of *.yml files. Can be supplied multiple times.",
)
@click.option(
    "-F",
    "--extra-profile-file",
    multiple=True,
    help="Path to a file containing extra profiles. Can be supplied multiple times.",
)
@click.option(
    "-U",
    "--update-profile",
    multiple=True,
    help="Update single values of the effective profile collection using yamlpath. Example: `shares.admin.crawl_depth=5`. Can be supplied multiple times.",
)
@click.option(
    "-n",
    "--dry-run",
    is_flag=True,
    help="Show the effective profile collection, credentials and other details, but do nothing else",
)
@click.option(
    "-i",
    "--input",
    help="input from list of hosts/networks (use - for stdin);"
    " can either be XML output from nmap or a target"
    " specification on each line",
)
@click.argument(
    "target",
    nargs=-1,
)
def crawl(
    ctx,
    user,
    domain,
    password,
    hash,
    force,
    timeout,
    threads,
    depth,
    check_write_access,
    disable_autodownload,
    extra_profile_directory,
    extra_profile_file,
    update_profile,
    dry_run,
    input,
    target,
):
    """Start crawling shares for secrets

    A target can be a host name, a single IP address, or an IP range in CIDR
    notation. An optional port can be specified in the usual form.
    """
    from smbcrawler.app import CrawlerApp, Login
    from smbcrawler.log import init_logger
    from smbcrawler.profiles import collect_profiles

    click.echo("Starting the crawler ...")
    init_logger()
    profile_collection = collect_profiles(
        extra_profile_directory, extra_profile_file, update_profile
    )

    app = CrawlerApp(
        Login(user, domain, password, hash),
        targets=target,
        crawl_file=ctx.parent.params["crawl_file"],
        threads=threads,
        timeout=timeout,
        depth=depth,
        check_write_access=check_write_access,
        crawl_printers_and_pipes=False,
        disable_autodownload=disable_autodownload,
        profile_collection=profile_collection,
        force=force,
        inputfilename=input,
        cmd=None,
    )

    if dry_run:
        app.dry_run()
    else:
        app.run()


@click.command(**help_alias)
def showlog():
    """Show the log file"""
    click.echo("Log file ...")


@click.command(**help_alias)
def export():
    """Export results to other file formats"""
    click.echo("Exporting ...")


cli.add_command(crawl)
cli.add_command(showlog)
cli.add_command(export)
