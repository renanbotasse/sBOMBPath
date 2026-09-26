"""Auth services."""

import jwt


SECRET_KEY = "fixture-secret"


def validate_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
