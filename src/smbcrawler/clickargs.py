import click


@click.group()
@click.option(
    "-C",
    "--crawl-file",
    default="output.crwl",
    show_default=True,
    help="path to output file",
)
def cli(crawl_file):
    pass


@click.command()
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
    user,
    domain,
    password,
    hash,
    force,
    timeout,
    threads,
    depth,
    check_write_access,
    input,
    target,
):
    """Start crawling shares for secrets

    A target can be a host name, a single IP address, or an IP range in CIDR
    notation. An optional port can be specified in the usual form.
    """
    click.echo("Starting the crawler ...")


@click.command()
def export():
    """Export results to other file formats"""
    click.echo("Exporting ...")


cli.add_command(crawl)
cli.add_command(export)
