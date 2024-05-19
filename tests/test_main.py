import pytest


@pytest.mark.parametrize("filter_crawl_result", [{"label": "base"}], indirect=True)
def test_base_guest_access(filter_crawl_result):
    data = filter_crawl_result["data"]

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
    data = filter_crawl_result["data"]
    assert data


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


# Test all the secret regexes contained in the default profile
@pytest.mark.parametrize(
    "content,expected",
    [
        ("foo <Password><Value>thesecret</Value></Password bar", "thesecret"),
        ("net use /user:admin thesecret x:", "thesecret"),
        ("foo runas /user:admin thesecret", "thesecret"),
        ("foo RunAs.exe /user:admin thesecret", "thesecret"),
        ("foo ConvertTo-SecureString thesecret", "thesecret"),
        ("foo password=thesecret bar", "thesecret"),
        ("foo password = thesecret bar", "thesecret"),
        ("----- BEGIN PRIVATE KEY -----", None),
        ("----- BEGIN RSA PRIVATE KEY -----", None),
        ("foo https://username:thesecret@host:80/fs bar", "thesecret"),
        ("foo http://user:pass@hostname.com", "user:pass"),
        ("foo https://user:pass@192.168.1.1 bar", "user:pass"),
        ("foo ftp://user:pass@ftp.server.com bar", "user:pass"),
        ("foo git+ssh://user:pass@ftp.server.com bar", "user:pass"),
        ('foo cpassword="ABKRDJALKSasldkdsfa8924+sdf/fsdfk3=" bar', None),
        ("foo <adminpass>thesecret</adminpass> bar", "thesecret"),
        ("    password: thesecret", "thesecret"),
        ('foo    "passwd": "thesecret"', "thesecret"),
        ("foo Kennwort: thesecret", "thesecret"),
        ("foo PASSWORD_SETUP=thesecret", "thesecret"),
        ("foo PASSWORD_EIS=thesecret", "thesecret"),
        ("foo k4AlddsflASkfwwSNdsflASkfwwSNsfl+/ASkfwwSNFslkfd2392=", None),
        ("foo k4AlddsflASkfwwSNdsflASkfwwSNsfl+/ASkfwwSNFslkfd2392", None),
    ],
)
def test_profile_secrets(content, expected, profile_collection):
    from smbcrawler.io import find_secrets

    result = find_secrets(content, profile_collection["secrets"])

    assert result
    result = result[0]
    assert result["line"] in content
    if expected:
        assert expected in result["secret"]
