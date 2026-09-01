import hashlib
from datetime import datetime, timezone

import database
import session


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def register(email, password):
    email = email.strip().lower()
    if database.get_user_by_email(email) is not None:
        raise ValueError("An account with this email already exists")
    created_at = datetime.now(timezone.utc).isoformat()
    user_id = database.create_user(email, hash_password(password), created_at)
    return database.get_user_by_id(user_id)


def login(email, password):
    email = email.strip().lower()
    user = database.get_user_by_email(email)
    if user is None or user["password_hash"] != hash_password(password):
        return None
    token = session.create_session(user)
    return token


def logout(token):
    session.destroy_session(token)


def require_user(token):
    user = session.get_current_user(token)
    if user is None:
        raise PermissionError("Not authenticated")
    return user
