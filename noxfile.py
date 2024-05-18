import nox

nox.options.default_venv_backend = "uv|virtualenv"


@nox.session()
def tests(session):
    session.install("-e", ".[tests]")
    session.run("pytest", *session.posargs)


@nox.session()
def format(session):
    session.install("ruff")
    session.run("ruff", "format", "--check", "src", *session.posargs)
    session.run("ruff", "format", "--check", "tests", *session.posargs)


@nox.session()
def lint(session):
    session.install("ruff")
    session.run("ruff", "check", "src", *session.posargs)
    session.run("ruff", "check", "tests", *session.posargs)
