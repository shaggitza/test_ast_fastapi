"""
Request Context Dependencies Example

This example demonstrates extracting and using request context information
like headers, cookies, client info, and request state.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, Request, Header, Cookie, HTTPException

app = FastAPI(title="Request Context Example")


def get_request_id(x_request_id: str | None = Header(None)) -> str:
    """Extract or generate request ID for tracking."""
    import uuid

    if x_request_id:
        return x_request_id
    return str(uuid.uuid4())


def get_user_agent(user_agent: str | None = Header(None)) -> str:
    """Extract user agent from headers."""
    return user_agent or "Unknown"


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    # Check X-Forwarded-For header first (for proxied requests)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    # Fall back to direct client
    if request.client:
        return request.client.host
    return "unknown"


def get_session_token(session_token: str | None = Cookie(None)) -> str | None:
    """Extract session token from cookie."""
    return session_token


def get_request_context(
    request_id: Annotated[str, Depends(get_request_id)],
    user_agent: Annotated[str, Depends(get_user_agent)],
    client_ip: Annotated[str, Depends(get_client_ip)],
    session_token: Annotated[str | None, Depends(get_session_token)],
) -> dict:
    """
    Aggregate request context from multiple sources.
    This is a composite dependency that depends on other context dependencies.
    """
    return {
        "request_id": request_id,
        "user_agent": user_agent,
        "client_ip": client_ip,
        "has_session": session_token is not None,
        "session_token": session_token,
    }


def validate_session(
    session_token: Annotated[str | None, Depends(get_session_token)]
) -> dict:
    """Validate session token and return session data."""
    if not session_token:
        raise HTTPException(status_code=401, detail="Session required")

    # In real app, validate token and fetch session data
    if session_token != "valid-session":
        raise HTTPException(status_code=401, detail="Invalid session")

    return {
        "user_id": 123,
        "username": "johndoe",
        "session_token": session_token,
    }


def log_request(context: Annotated[dict, Depends(get_request_context)]) -> dict:
    """Log request details and return context."""
    import logging

    logger = logging.getLogger(__name__)
    logger.info(
        f"Request {context['request_id']} from {context['client_ip']} "
        f"using {context['user_agent']}"
    )
    return context


# Type aliases
RequestContext = Annotated[dict, Depends(get_request_context)]
LoggedContext = Annotated[dict, Depends(log_request)]
ValidSession = Annotated[dict, Depends(validate_session)]


@app.get("/info")
def request_info(context: RequestContext) -> dict:
    """Get information about the current request."""
    return {
        "message": "Request information",
        "context": context,
    }


@app.get("/tracked")
def tracked_endpoint(context: LoggedContext) -> dict:
    """Endpoint with automatic request logging."""
    return {
        "message": "This request was logged",
        "request_id": context["request_id"],
    }


@app.get("/profile")
def get_profile(session: ValidSession, context: RequestContext) -> dict:
    """Get user profile (requires valid session)."""
    return {
        "user": {
            "id": session["user_id"],
            "username": session["username"],
        },
        "request_context": context,
    }


@app.post("/action")
def perform_action(
    action: dict,
    session: ValidSession,
    context: LoggedContext,
) -> dict:
    """Perform an action with session validation and request logging."""
    return {
        "action": action,
        "user_id": session["user_id"],
        "request_id": context["request_id"],
        "success": True,
    }
