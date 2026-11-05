"""API v1 router registry."""

from fastapi import APIRouter

from app.routers import assets, demo, evidence, sanitization_jobs, sanitization_records, scheduling, system

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(assets.router)
api_router.include_router(scheduling.router)
api_router.include_router(sanitization_records.asset_records_router)
api_router.include_router(sanitization_records.router)
api_router.include_router(sanitization_jobs.router)
api_router.include_router(evidence.record_verifications_router)
api_router.include_router(evidence.verification_certificates_router)
api_router.include_router(evidence.asset_custody_router)
api_router.include_router(evidence.asset_disposition_router)
api_router.include_router(evidence.router)
api_router.include_router(demo.asset_demo_router)
api_router.include_router(demo.job_demo_router)
api_router.include_router(demo.record_demo_router)
api_router.include_router(demo.demo_router)
api_router.include_router(demo.dashboard_router)
