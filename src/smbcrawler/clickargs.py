import click

from smbcrawler.version import __version__


help_alias = dict(context_settings=dict(help_option_names=["-h", "--help"]))


def deactivate_password_prompt(ctx, param, value):
    if value:
        for p in ctx.command.params:
            if p.name == "password":
                p.prompt = None
    return value


@click.group(**help_alias)
@click.version_option(__version__)
@click.option(
    "-d",
    "--debug",
    is_flag=True,
    help="Show debug output (implies --verbose)",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Show verbose output",
)
@click.option(
    "-C",
    "--crawl-file",
    type=click.Path(dir_okay=False),
    default="output.crwl",
    show_default=True,
    help="Path to output file",
)
def cli(debug, verbose, crawl_file):
    pass


@click.command(**help_alias)
@click.pass_context
@click.option(
    "-u",
    "--user",
    default=" ",
    help="User name, if omitted we'll try a null session",
)
@click.option(
    "-d",
    "--domain",
    default=".",
    show_default=True,
    help="The user's domain",
)
@click.option(
    "-p",
    "--password",
    default="",
    prompt=True,
    hide_input=True,
    help="Password, if omitted you'll be prompted]",
)
@click.option(
    "-H",
    "--nthash",
    help="NT hash, can be used instead of a password",
    callback=deactivate_password_prompt,
)
@click.option(
    "-f",
    "--force",
    default=False,
    is_flag=True,
    help="Always keep going after STATUS_LOGON_FAILURE occurs",
)
@click.option(
    "-T",
    "--timeout",
    type=int,
    default=5,
    show_default=True,
    help="Timeout in seconds when attempting to connect to an SMB service",
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
    help="Crawling depth; 0 lists only share names and no directories or "
    "files, -1 lists everything",
)
@click.option(
    "-m",
    "--max-file-size",
    default=200,
    type=int,
    show_default=True,
    help="Maximum size of downloaded files in KiBi (except high value files)",
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
    type=click.Path(exists=True, file_okay=False),
    multiple=True,
    help="Path to a directory containing extra profiles in the form of *.yml files. Can be supplied multiple times.",
)
@click.option(
    "-F",
    "--extra-profile-file",
    type=click.Path(exists=True, dir_okay=False),
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
    type=click.Path(exists=True, dir_okay=False, allow_dash=True),
    help="input from list of hosts/networks (use - for stdin);"
    " can either be XML output from nmap or a target"
    " specification on each line",
)
@click.option(
    "-N",
    "--no-default",
    is_flag=True,
    help="Do not load default profiles",
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
    nthash,
    force,
    timeout,
    threads,
    depth,
    max_file_size,
    check_write_access,
    disable_autodownload,
    extra_profile_directory,
    extra_profile_file,
    update_profile,
    dry_run,
    input,
    target,
    no_default,
):
    """Start crawling shares for secrets

    A target can be a host name, a single IP address, or an IP range in CIDR
    notation. An optional port can be specified in the usual form.
    """
    import shlex
    import sys
    import logging
    from smbcrawler.app import CrawlerApp, Login
    from smbcrawler.log import init_logger
    from smbcrawler.profiles import collect_profiles

    log_level = "WARN"
    if ctx.parent.params["verbose"]:
        log_level = "INFO"
    if ctx.parent.params["debug"]:
        log_level = "DEBUG"
    init_logger(log_level=log_level)
    logger = logging.getLogger(__name__)

    profile_collection = collect_profiles(
        extra_dirs=extra_profile_directory,
        extra_files=extra_profile_file,
        update_queries=update_profile,
        load_default=not no_default,
    )

    cmd = " ".join(
        shlex.quote(arg if arg not in [password, nthash] else "***") for arg in sys.argv
    )
    logger.info(f"Starting up with these arguments: {cmd}")

    app = CrawlerApp(
        Login(user, domain, password, nthash),
        targets=target,
        crawl_file=ctx.parent.params["crawl_file"],
        threads=threads,
        timeout=timeout,
        depth=depth,
        max_file_size=max_file_size * 1024,
        check_write_access=check_write_access,
        disable_autodownload=disable_autodownload,
        profile_collection=profile_collection,
        force=force,
        inputfilename=input,
        cmd=cmd,
    )

    if dry_run:
        app.dry_run()
    else:
        app.run()


@click.command(**help_alias)
@click.pass_context
def showlog(ctx):
    """Show the log file"""
    from smbcrawler.reporting import show_log

    show_log(ctx.parent.params["crawl_file"])


@click.command(**help_alias)
@click.pass_context
@click.option(
    "-f",
    "--format",
    type=click.Choice(["html", "json", "yaml", "csv"]),
    default="yaml",
    show_default=True,
    help="Output format",
)
@click.option(
    "-s",
    "--section",
    type=click.Choice(
        [
            "summary",
            "targets",
            "shares",
            "secrets",
            "secrets_unique",
            "secrets_cleanup_guide",
            "high_value_files",
        ]
    ),
    default="summary",
    help="Only output this section of the report",
)
@click.argument("outputfile", type=click.File("w"), default="-")
def report(ctx, format, section, outputfile):
    """Export results to other file formats"""
    from smbcrawler.reporting import generate

    generate(ctx.parent.params["crawl_file"], format, outputfile, section=section)


for command in [crawl, showlog, report]:
    cli.add_command(command)
