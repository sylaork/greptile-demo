import secrets
from datetime import datetime, timezone

import database


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    database.insert_session(token, user_id)
    return token


def get_session(token):
    record = database.fetch_session(token)
    if record is None:
        return None
    expires_at = datetime.fromisoformat(record["expires_at"])
    if datetime.now(timezone.utc) >= expires_at:
        database.delete_session(token)
        return None
    return record


def destroy_session(token):
    database.delete_session(token)


def get_current_user(token):
    record = get_session(token)
    if record is None:
        return None
    return database.get_user_by_id(record["user_id"])
