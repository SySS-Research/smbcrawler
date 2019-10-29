import pytest


def pytest_addoption(parser):
    parser.addoption("--testcase", action="store")


@pytest.fixture(scope='session')
def testcase(request):
    value = request.config.option.testcase
    return value
