"""HTTP routes for the local secure-notes lab."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.responses import Response as StarletteResponse

from secure_notes import __version__
from secure_notes.config import Settings, load_settings
from secure_notes.database import Database
from secure_notes.messages import (
    AUTHENTICATION_REQUIRED,
    INTERNAL_ERROR,
    INVALID_CREDENTIALS,
    NOTE_NOT_FOUND,
    REGISTER_FAILED,
    TOO_MANY_REQUESTS,
)
from secure_notes.models import (
    LoginRequest,
    NoteCreateRequest,
    NoteResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from secure_notes.rate_limit import InMemoryFixedWindowRateLimiter, RateLimiter
from secure_notes.records import AuthenticatedUser, NoteRecord
from secure_notes.redaction import configure_logging, get_logger
from secure_notes.service import (
    AuthenticationFailed,
    NotesService,
    NoteUnavailable,
    RegistrationRejected,
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), microphone=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}


@dataclass
class LabState:
    """Objects that live for one process."""

    settings: Settings
    database: Database
    limiter: RateLimiter
    service: NotesService


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the lab API.

    Passing ``settings`` is how tests supply an isolated database. The
    default path reads ``NOTES_SECRET_KEY`` from the environment.
    """

    resolved = settings if settings is not None else load_settings()
    database = Database.connect(resolved.database_path)
    limiter = InMemoryFixedWindowRateLimiter(
        limit=resolved.rate_limit_requests,
        window_seconds=float(resolved.rate_limit_window_seconds),
    )
    state = LabState(
        settings=resolved,
        database=database,
        limiter=limiter,
        service=NotesService(database, resolved),
    )
    configure_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        lab = getattr(app.state, "lab", None)
        if isinstance(lab, LabState):
            lab.database.close()

    app = FastAPI(
        title="Secure Notes Lab",
        version=__version__,
        description=(
            "Local teaching API for defensive security. "
            "Not a production service. Do not store real secrets in it."
        ),
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.lab = state
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unhandled_error)

    @app.middleware("http")
    async def add_security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[StarletteResponse]],
    ) -> StarletteResponse:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/register", status_code=201, response_model=UserResponse)
    def register(body: RegisterRequest, request: Request) -> UserResponse:
        _enforce_rate_limit(request)
        try:
            user = _state(request).service.register(body.username, body.password)
        except RegistrationRejected:
            raise HTTPException(status_code=400, detail=REGISTER_FAILED) from None
        return UserResponse(id=user.id, username=user.username)

    @app.post("/auth/login", response_model=TokenResponse)
    def login(body: LoginRequest, request: Request) -> TokenResponse:
        _enforce_rate_limit(request)
        try:
            token, expires_in = _state(request).service.login(body.username, body.password)
        except AuthenticationFailed:
            raise HTTPException(
                status_code=401,
                detail=INVALID_CREDENTIALS,
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        return TokenResponse(token=token, expires_in=expires_in)

    @app.post("/notes", status_code=201, response_model=NoteResponse)
    def create_note(
        body: NoteCreateRequest,
        request: Request,
        user: Annotated[AuthenticatedUser, Depends(_current_user)],
    ) -> NoteResponse:
        note = _state(request).service.create_note(user, body.title, body.body)
        return _public_note(note)

    @app.get("/notes", response_model=list[NoteResponse])
    def list_notes(
        request: Request,
        user: Annotated[AuthenticatedUser, Depends(_current_user)],
    ) -> list[NoteResponse]:
        return [_public_note(note) for note in _state(request).service.list_notes(user)]

    @app.get("/notes/{note_id}", response_model=NoteResponse)
    def read_note(
        note_id: str,
        request: Request,
        user: Annotated[AuthenticatedUser, Depends(_current_user)],
    ) -> NoteResponse:
        try:
            note = _state(request).service.get_note(user, note_id)
        except NoteUnavailable:
            raise HTTPException(status_code=404, detail=NOTE_NOT_FOUND) from None
        return _public_note(note)

    @app.delete("/notes/{note_id}", status_code=204)
    def delete_note(
        note_id: str,
        request: Request,
        user: Annotated[AuthenticatedUser, Depends(_current_user)],
    ) -> Response:
        try:
            _state(request).service.delete_note(user, note_id)
        except NoteUnavailable:
            raise HTTPException(status_code=404, detail=NOTE_NOT_FOUND) from None
        return Response(status_code=204)

    return app


def _state(request: Request) -> LabState:
    lab = getattr(request.app.state, "lab", None)
    if not isinstance(lab, LabState):
        raise RuntimeError("lab state is not initialized")
    return lab


def _client_address(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host


def _enforce_rate_limit(request: Request) -> None:
    """Limit registration and login for this peer and path.

    The forwarded-for header is ignored. A client can set it to any value,
    so it is not a trustworthy identity.
    """

    state = _state(request)
    key = f"{_client_address(request)}:{request.url.path}"
    if state.limiter.allow(key):
        return
    state.service.record_rate_limit()
    raise HTTPException(
        status_code=429,
        detail=TOO_MANY_REQUESTS,
        headers={"Retry-After": str(state.settings.rate_limit_window_seconds)},
    )


def _current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> AuthenticatedUser:
    token = _bearer_token(authorization)
    user = _state(request).service.authenticate_token(token)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail=AUTHENTICATION_REQUIRED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def _bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise HTTPException(
            status_code=401,
            detail=AUTHENTICATION_REQUIRED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, separator, rest = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail=AUTHENTICATION_REQUIRED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = rest.strip()
    if token == "" or any(character.isspace() for character in token):
        raise HTTPException(
            status_code=401,
            detail=AUTHENTICATION_REQUIRED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def _public_note(note: NoteRecord) -> NoteResponse:
    return NoteResponse(
        id=note.id,
        title=note.title,
        body=note.body,
        created_at=note.created_at,
    )


def _validation_error(_request: Request, exc: Exception) -> JSONResponse:
    """Describe invalid fields without echoing the submitted values.

    FastAPI's default error body includes the input. A short password would
    otherwise be copied into the response.
    """

    if not isinstance(exc, RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Invalid request"})
    cleaned: list[dict[str, object]] = []
    for error in exc.errors():
        location = error.get("loc", ())
        cleaned.append(
            {
                "loc": [str(item) for item in location],
                "msg": str(error.get("msg", "Invalid value")),
                "type": str(error.get("type", "value_error")),
            }
        )
    return JSONResponse(status_code=422, content={"detail": cleaned})


def _unhandled_error(_request: Request, exc: Exception) -> JSONResponse:
    """Return a fixed message. The exception text stays off the wire."""

    if isinstance(exc, HTTPException):
        headers = dict(exc.headers) if exc.headers is not None else None
        detail = exc.detail if isinstance(exc.detail, str) else INTERNAL_ERROR
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": detail},
            headers=headers,
        )
    get_logger().error("unhandled error type=%s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": INTERNAL_ERROR})
