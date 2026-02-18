from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import CORS_ORIGINS
from routers import scan, qr, bulk

app = FastAPI(
    title="Risk Analyzer API",
    description="Phishing Detection & Risk Scoring System",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, prefix="/scan", tags=["scan"])
app.include_router(qr.router, prefix="/scan", tags=["qr"])
app.include_router(bulk.router, prefix="/scan", tags=["bulk"])


@app.get("/")
def health_check():
    return {"status": "ok", "service": "risk-analyzer-api"}
