import nox


@nox.session()
def tests(session):
    session.install(".[tests]")
    session.run("pytest", *session.posargs)


@nox.session()
def lint(session):
    session.install("black")
    session.run("black", "smbcrawler", "--check", *session.posargs)
    session.run("black", "tests", "--check", *session.posargs)
