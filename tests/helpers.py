"""دوال مساعدة لاختبارات المنصة عبر TestClient."""


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def signup(api, name="منشأة"):
    r = api.post("/api/v1/tenants", json={"name": name})
    assert r.status_code == 201
    return r.json()
