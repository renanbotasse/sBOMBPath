"""Auth views with JWT sink."""

from apps.auth.services import validate_token


class RefreshTokenView:
    def post(self, request):
        token = request.data["token"]
        decoded = validate_token(token)
        return decoded
