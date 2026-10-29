import pytest

from sandbox_firewall import DEFAULT_ALLOWLIST
from tenancy.auth import RateLimiter, StreamTokens
from tenancy.registry import DASHBOARD, INGEST, TENANT_ID_RE, Registry
from tenancy.store import TenantStore


@pytest.fixture
def reg(tmp_path):
    return Registry(tmp_path / "registry.db")


def test_create_returns_prefixed_keys_and_valid_id(reg):
    tenant, keys = reg.create("  مقهى الريف  ")
    assert TENANT_ID_RE.fullmatch(tenant.id) and tenant.name == "مقهى الريف"
    assert keys["ingest_key"].startswith("pc_ing_") and keys["dashboard_key"].startswith("pc_dash_")


def test_resolve_identifies_tenant_and_kind(reg):
    tenant, keys = reg.create("أ")
    assert reg.resolve(keys["dashboard_key"]) == (tenant, DASHBOARD)
    assert reg.resolve(keys["ingest_key"]) == (tenant, INGEST)
    for bad in ("", "random", "pc_dash_wrong", keys["dashboard_key"] + "x"):
        assert reg.resolve(bad) is None


def test_only_hashes_are_stored(tmp_path):
    path = tmp_path / "registry.db"
    _, keys = Registry(path).create("أ")
    raw = path.read_bytes()
    assert keys["ingest_key"].encode() not in raw and keys["dashboard_key"].encode() not in raw


def test_rotate_invalidates_old_keys(reg):
    tenant, old = reg.create("أ")
    new = reg.rotate(tenant.id)
    assert reg.resolve(old["dashboard_key"]) is None and reg.resolve(old["ingest_key"]) is None
    assert reg.resolve(new["dashboard_key"]) == (tenant, DASHBOARD)


def test_name_is_validated(reg):
    for bad in ("   ", "x" * 81):
        with pytest.raises(ValueError):
            reg.create(bad)


def test_store_rejects_bad_tenant_ids(tmp_path):
    store = TenantStore(tmp_path)
    for bad in ("../x", "t_ABCDEFGHIJKL", "t_short", "t_abcdefghijkl/../x", ""):
        with pytest.raises(ValueError):
            store.dir(bad)


def test_settings_default_and_roundtrip(tmp_path):
    store, tid = TenantStore(tmp_path), "t_abcdefghijkl"
    assert store.settings(tid) == {"webhook_url": None, "allowlist": list(DEFAULT_ALLOWLIST)}
    store.save_settings(tid, {"webhook_url": "https://x.test/hook", "allowlist": ["10.0.0.1"]})
    assert store.settings(tid) == {"webhook_url": "https://x.test/hook", "allowlist": ["10.0.0.1"]}
    assert (tmp_path / tid / "tenant.db").exists()


def test_stream_token_is_single_use_scoped_and_expiring():
    now = [0.0]
    tokens = StreamTokens(clock=lambda: now[0])
    t = tokens.issue("t_a", "inc1")
    assert tokens.consume(t, "inc2") is None              # حادثة أخرى، والرمز يُحرق
    t = tokens.issue("t_a", "inc1")
    assert tokens.consume(t, "inc1") == "t_a"
    assert tokens.consume(t, "inc1") is None              # مرة واحدة فقط
    t = tokens.issue("t_a", "inc1")
    now[0] = StreamTokens.TTL + 1
    assert tokens.consume(t, "inc1") is None              # منتهٍ


def test_rate_limiter_window():
    now = [0.0]
    limiter = RateLimiter(limit=2, window=10, clock=lambda: now[0])
    assert limiter.allow("ip") and limiter.allow("ip") and not limiter.allow("ip")
    assert limiter.allow("other")
    now[0] = 11
    assert limiter.allow("ip")
