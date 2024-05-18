import pytest


@pytest.mark.parametrize("filter_crawl_result", [{"label": "base"}], indirect=True)
def test_base_guest_access(filter_crawl_result):
    data = filter_crawl_result["data"]
    breakpoint()

    for share in data["share"]:
        if share["target_id"] == "127.1.0.2:445" and share["name"] == "small":
            assert not share["guest_access"]
        if share["target_id"] == "127.1.0.3:445" and share["name"] == "small":
            assert share["guest_access"]

    for target in data["target"]:
        if target["name"] == "127.1.0.1:445":
            assert target["listable_authenticated"]
            assert not target["listable_unauthenticated"]
        if target["name"] == "127.1.0.2:445":
            assert target["listable_unauthenticated"]
        if target["name"] == "127.1.0.3:445":
            assert target["listable_unauthenticated"]


@pytest.mark.parametrize("filter_crawl_result", [{"label": "full"}], indirect=True)
def test_full(filter_crawl_result):
    pass


@pytest.fixture
def profile_collection():
    from smbcrawler.profiles import collect_profiles

    profile_collection = collect_profiles()
    yield profile_collection


def test_profile_high_value_file(profile_collection):
    from smbcrawler.profiles import find_matching_profile

    profile = find_matching_profile(profile_collection, "files", "SAM")
    assert profile["comment"] == "Windows user database"
    assert profile["high_value"]
