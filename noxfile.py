import nox
nox.options.default_venv_backend = "uv|virtualenv"


@nox.session()
def tests(session):
    session.install(".[tests]")
    session.run("pytest", *session.posargs)


@nox.session()
def format(session):
    session.install("black")
    session.run("black", "src", "--check", *session.posargs)
    session.run("black", "tests", "--check", *session.posargs)


@nox.session()
def lint(session):
    session.install("ruff")
    session.run("ruff", "check", "src", *session.posargs)
    session.run("ruff", "check", "tests", *session.posargs)
