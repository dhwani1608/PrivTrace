"""Phase 10: Verify (canary deletion test) logic, with an in-memory fake app and fake stores."""

import httpx

from privtrace.verify.canary import HttpStep, StoresConfig, VerifyConfig, dig, render, run_verify


def test_render_and_dig():
    v = {"canary": "abc", "user_id": 7}
    assert render({"email": "{canary}@example.com", "id": "{user_id}", "l": ["{user_id}"]}, v) == \
        {"email": "abc@example.com", "id": 7, "l": [7]}
    assert render("/users/{user_id}", v) == "/users/7"
    assert dig({"a": [{"b": 3}]}, "a.0.b") == 3


def make_app(erase_cache: bool):
    """A fake app: signup stores in db + cache; delete removes db row and (optionally) cache."""
    db: dict[int, str] = {}
    cache: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        import json
        if req.method == "POST" and req.url.path == "/signup":
            body = json.loads(req.content)
            db[1] = body["email"]
            cache["profile:1"] = body["email"]
            return httpx.Response(200, json={"id": 1})
        if req.method == "DELETE" and req.url.path == "/users/1":
            db.pop(1, None)
            if erase_cache:
                cache.pop("profile:1", None)
            return httpx.Response(200, json={"deleted": 1})
        return httpx.Response(404)

    searchers = {
        "postgres": lambda c: (any(c in v for v in db.values()), ""),
        "redis": lambda c: (any(c in v for v in cache.values()), ""),
        "logs": lambda c: (False, ""),
    }
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://app")
    return client, searchers


CFG = VerifyConfig(
    name="fake", base_url="http://app",
    signup=HttpStep(path="/signup", json={"email": "{canary}@example.com"}, save={"user_id": "id"}),
    delete=HttpStep(method="DELETE", path="/users/{user_id}"),
    stores=StoresConfig(), settle_seconds=0,
)


def test_verify_fails_store_that_keeps_data():
    client, searchers = make_app(erase_cache=False)
    rep = run_verify(CFG, searchers=searchers, client=client, sleep=lambda s: None)
    by = {r.store: r for r in rep.results}
    assert by["postgres"].status == "PASS" and by["postgres"].found_before_delete
    assert by["redis"].status == "FAIL" and by["redis"].found_after_delete
    assert by["logs"].status == "PASS" and "never reached" in by["logs"].detail
    assert not rep.passed and rep.user_id == 1


def test_verify_passes_when_everything_erased():
    client, searchers = make_app(erase_cache=True)
    rep = run_verify(CFG, searchers=searchers, client=client, sleep=lambda s: None)
    assert rep.passed and all(r.status == "PASS" for r in rep.results)


def test_verify_reports_http_errors():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)), base_url="http://app")
    rep = run_verify(CFG, searchers={}, client=client, sleep=lambda s: None)
    assert rep.error and "HTTP 500" in rep.error and not rep.passed
