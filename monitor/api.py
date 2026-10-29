"""
نقاط المراقبة الخارجية (/api/v1/monitor) — داخل سياق المنشأة كبقية المنصة:
المنشأة من المفتاح فقط، وموقع منشأة أخرى يرجع 404.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from monitor.service import MonitorError
from tenancy.auth import dashboard_tenant

router = APIRouter(prefix="/api/v1/monitor")


class SiteReq(BaseModel):
    url: str


def _monitor(request: Request):
    return request.app.state.platform.monitor


def _call(fn, *args):
    try:
        return fn(*args)
    except MonitorError as e:
        headers = {"Retry-After": str(e.retry_after)} if e.retry_after else None
        raise HTTPException(e.status, str(e), headers=headers)


def _one(mon, tenant_id, site_id):
    return next(s for s in mon.summary(tenant_id) if s["id"] == site_id)


@router.get("/sites")
def sites(request: Request, tenant=Depends(dashboard_tenant)):
    return {"sites": _monitor(request).summary(tenant.id)}


@router.post("/sites", status_code=201)
def add_site(req: SiteReq, request: Request, tenant=Depends(dashboard_tenant)):
    mon = _monitor(request)
    site_id = _call(mon.add_site, tenant.id, req.url)
    mon.submit(tenant.id, site_id)   # أول فحص توفر بلا انتظار المجدول
    return _one(mon, tenant.id, site_id)


@router.delete("/sites/{site_id}")
def delete_site(site_id: int, request: Request, tenant=Depends(dashboard_tenant)):
    _call(_monitor(request).delete, tenant.id, site_id)
    return {"deleted": True}


@router.post("/sites/{site_id}/verify")
def verify(site_id: int, request: Request, tenant=Depends(dashboard_tenant)):
    mon = _monitor(request)
    result = _call(mon.verify, tenant.id, site_id)
    return {**result, "site": _one(mon, tenant.id, site_id)}


@router.post("/sites/{site_id}/check")
def check(site_id: int, request: Request, tenant=Depends(dashboard_tenant)):
    mon = _monitor(request)
    _call(mon.check_now, tenant.id, site_id)
    return _one(mon, tenant.id, site_id)
