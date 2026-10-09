import json

import pytest

from orchardwarden.ioc import IocIndex, feed, load_plain_list, load_stix_bundle
from orchardwarden.testing import make_ioc_bundle


def test_stix_load_and_domain_suffix_matching():
    idx = IocIndex()
    for i in load_stix_bundle(make_ioc_bundle()):
        idx.add(i)
    assert idx.match_domain("evil-example.test")
    assert idx.match_domain("a.b.EVIL-example.test.")
    assert idx.match_domain("notevil-example.test") is None
    assert idx.match_url("https://cdn.evil-example.test/x?y=1").kit == "coruna"
    assert idx.match_process("fakeimplantd")
    assert idx.match_domain("test") is None  # never match a bare TLD


def test_plain_list_types():
    inds = load_plain_list("# c\nexample.org\n1.2.3.4\nhttp://a.test/p\nuser@x.test\n" + "a" * 64)
    assert {i.kind for i in inds} == {"domain", "ip", "url", "email", "sha256"}


def test_signed_feed_roundtrip_tamper_and_wrong_key():
    priv, pub = feed.generate_keypair()
    env = feed.sign_bundle(make_ioc_bundle(), priv, "k1")
    assert feed.verify_envelope(env, {"k1": pub})["type"] == "bundle"

    tampered = dict(env)
    payload = json.loads(env["payload"])
    payload["objects"][0]["pattern"] = "[domain-name:value='benign.test']"
    tampered["payload"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    with pytest.raises(feed.FeedError):
        feed.verify_envelope(tampered, {"k1": pub})

    _, other_pub = feed.generate_keypair()
    with pytest.raises(feed.FeedError):
        feed.verify_envelope(env, {"k1": other_pub})
    with pytest.raises(feed.FeedError):
        feed.verify_envelope(env, {})
    with pytest.raises(feed.FeedError):
        feed.verify_envelope({"nope": 1}, {"k1": pub})
