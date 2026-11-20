from fastapi import Header, HTTPException


def get_current_user(authorization: str = Header(...)) -> int:
    """Demo stand-in for real authentication: returns the caller's user id from a verified token."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing token")
    return verify_token(authorization.removeprefix("Bearer "))


def verify_token(token: str) -> int:
    """Replace with your identity provider (e.g. Firebase Auth / Identity Platform)."""
    raise HTTPException(401, "token verification not configured")
