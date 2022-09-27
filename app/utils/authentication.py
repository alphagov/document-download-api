from flask import abort, current_app, request


def requires_auth(fn):
    def wrapper(*args, **kwargs):
        check_auth()
        return fn(*args, **kwargs)

    return wrapper


def check_auth():
    incoming_token = get_token_from_headers()

    if not incoming_token:
        abort(401, "Unauthorized; bearer token must be provided")
    elif not token_is_valid(incoming_token):
        abort(403, "Forbidden; invalid bearer token provided {}".format(incoming_token))


def token_is_valid(incoming_token):
    return incoming_token in get_allowed_tokens(current_app.config)


def get_allowed_tokens(config):
    """Return a list of allowed auth tokens from the application config"""
    return [token for token in (config.get("AUTH_TOKENS") or "").split(":") if token]


def get_token_from_headers():
    auth_header = request.headers.get("Authorization", "")
    if auth_header[:7] != "Bearer ":
        return None

    return auth_header[7:]
