import pytest


@pytest.mark.parametrize("filter_crawl_result", [{"label": "base"}], indirect=True)
def test_basics(filter_crawl_result):
    pass


@pytest.mark.parametrize("filter_crawl_result", [{"label": "full"}], indirect=True)
def test_full(filter_crawl_result):
    pass


def test_profile():
    from smbcrawler.profiles import collect_profiles, find_matching_profile

    profile_collection = collect_profiles()
    profile = find_matching_profile(profile_collection, "files", "SAM")
    assert profile["comment"] == "Windows user database"
