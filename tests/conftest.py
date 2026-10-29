import sys
from pathlib import Path

import joblib
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
CACHE = ROOT / "dashboard_cache"


@pytest.fixture(scope="session")
def data():
    if not (CACHE / "act_sample.parquet").exists():
        pytest.skip("شغّل prepare_dashboard_data.py أولًا")
    return (pd.read_parquet(CACHE / "act_sample.parquet"),
            pd.read_parquet(CACHE / "lstm_windows.parquet"))


@pytest.fixture(scope="session")
def resources(data):
    """موارد حقيقية لنموذج الكشف، وتنبؤ ثابت بدل LSTM (حتى لا تحمّل الاختبارات TensorFlow)."""
    from explain_decision import compute_baseline_stats
    from agent.tools import Resources
    tm = joblib.load(ROOT / "attack_type_model.joblib")
    act, windows = data
    benign = act[act["family"] == "BENIGN"]
    cols = [c for c in windows.columns if c not in ("attack_flows", "attack_next_window")]
    return Resources(model=tm["model"], feature_names=tm["feature_names"],
                     baseline=compute_baseline_stats(benign, tm["feature_names"]),
                     forecast_fn=lambda values: 0.5, forecast_cols=cols, threshold=0.1)


@pytest.fixture
def portscan(data):
    from agent.scenarios import build_incident
    return build_incident(*data, "PortScan", seed=1)


@pytest.fixture
def platform(tmp_path, resources, data):
    """منصة مؤقتة: مجلدات tmp_path، ووضع العرض، وتنبؤ ثابت (بلا TensorFlow ولا مفتاح Claude)."""
    from agent.demo import DemoClient
    from tenancy.api import Platform
    from tenancy.registry import Registry
    from tenancy.store import TenantStore
    act, windows = data
    return Platform(registry=Registry(tmp_path / "registry.db"), store=TenantStore(tmp_path / "tenants"),
                    resources=lambda: resources, act_sample=act, windows=windows,
                    client=lambda: DemoClient(), live=lambda: False)


@pytest.fixture
def api(platform):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from monitor.api import router as monitor_router
    from tenancy.api import router
    from tenancy.pages import pages
    app = FastAPI()
    app.include_router(router)
    app.include_router(pages)
    app.include_router(monitor_router)
    app.state.platform = platform
    return TestClient(app)
