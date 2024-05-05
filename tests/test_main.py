import pytest


@pytest.mark.parametrize("filter_crawl_result", [{"label": "base"}], indirect=True)
def test_basics(filter_crawl_result):
    pass


@pytest.mark.parametrize("filter_crawl_result", [{"label": "full"}], indirect=True)
def test_full(filter_crawl_result):
    pass
