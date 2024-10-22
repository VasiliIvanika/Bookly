from contextlib import asynccontextmanager
from  fastapi import  FastAPI
from src.books.views import book_router
from src.auth.views import auth_router
from src.db.main import init_db


@asynccontextmanager
async def life_span(app: FastAPI):
    print(f"server is starting...")
    await init_db()
    yield
    print(f"server has been stopped")


version = "v1"

app = FastAPI(
    title="Bookly",
    description="a rest api for a book review web service",
    version=version,
    lifespan=life_span,
)

app.include_router(
    book_router,
    prefix=f"/api/{version}/books",
    tags=["books"],
)
app.include_router(
    auth_router,
    prefix=f"/api/{version}/auth",
    tags=["auth"],
)