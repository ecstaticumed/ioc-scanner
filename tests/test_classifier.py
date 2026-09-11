import sys

sys.path.append("src")

from classifier import classify_ioc


def test_ipv4():
    assert classify_ioc("8.8.8.8") == "ip"


def test_ipv6():
    assert classify_ioc("2001:4860:4860::8888") == "ip"


def test_domain():
    assert classify_ioc("example.com") == "domain"


def test_url():
    assert classify_ioc("https://example.com/login") == "url"


def test_md5():
    assert (
        classify_ioc(
            "d41d8cd98f00b204e9800998ecf8427e"
        )
        == "md5"
    )


def test_sha1():
    assert (
        classify_ioc(
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        )
        == "sha1"
    )


def test_unknown():
    assert classify_ioc("not-an-ioc") == "unknown"
