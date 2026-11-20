import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import history, service
from .workspace import ASSETS


@asynccontextmanager
async def lifespan(app):
    async def loop():
        while True:
            await asyncio.to_thread(service.work)
            await asyncio.sleep(0.4)

    worker = asyncio.create_task(loop())
    try:
        yield
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)


app = FastAPI(lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])


class Submission(BaseModel):
    repository: str
    scope: list[str] | None = None
    idempotency_key: str | None = Field(None, max_length=200)


@app.post("/scans", status_code=202)
def submit(body: Submission):
    repo = str(Path(body.repository).resolve())
    with history.database() as db:
        if not db.execute("SELECT 1 FROM repositories WHERE path=?", (repo,)).fetchone():
            raise HTTPException(403, "Register the local repository with the CLI first")
    try:
        return {"id": service.enqueue(repo, body.scope, body.idempotency_key, "API snapshot")}
    except history.Conflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(422, "Unsupported repository or scope") from exc


@app.get("/repositories")
def repositories():
    with history.database() as db:
        return [r[0] for r in db.execute("SELECT path FROM repositories ORDER BY path")]


@app.get("/scans")
def scans():
    return history.listing()


@app.get("/scans/{sid}")
def scan(sid: str):
    try:
        return history.detail(sid)
    except KeyError as exc:
        raise HTTPException(404, "Unknown scan") from exc


@app.post("/scans/{sid}/retry", status_code=202)
def retry(sid: str):
    try:
        service.retry(sid)
    except (ValueError, KeyError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"id": sid, "status": "queued"}


@app.get("/events")
def events(after: int = 0):
    return history.events(max(after, 0))


dist = ASSETS / "dashboard"
if (dist / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")


@app.get("/")
@app.get("/review/{sid}")
@app.get("/review/{sid}/repair")
def dashboard(sid: str = ""):
    if not (dist / "index.html").exists():
        raise HTTPException(503, "Build the frontend with npm run build")
    return FileResponse(dist / "index.html")


@app.get("/dashboard")
def dashboard_page():
    if not (dist / "index.html").exists():
        raise HTTPException(503, "Build the frontend with npm run build")
    return FileResponse(dist / "index.html")


@app.get("/image.png")
def image():
    return FileResponse(
        Path("/media/rajath-r-prasad/OS1/projects/hackathon/laundromat/Frontend/public/image.png")
    )
