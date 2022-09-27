from unittest import mock

from app.utils.authentication import (
    check_auth,
    get_allowed_tokens,
    get_token_from_headers,
    requires_auth,
    token_is_valid,
)
from tests.conftest import set_config


def test_unknown_token_is_not_valid(app):
    with set_config(app, AUTH_TOKENS="valid"):
        assert not token_is_valid("invalid")


def test_token_is_valid(app):
    with set_config(app, AUTH_TOKENS="token-1:token-2"):
        assert token_is_valid("token-1")
        assert token_is_valid("token-2")


def test_empty_token_is_invalid(app):
    with set_config(app, AUTH_TOKENS="valid"):
        assert not token_is_valid(None)
        assert not token_is_valid("")


def test_get_allowed_tokens(app):
    with set_config(app, AUTH_TOKENS="valid1:valid2"):
        assert get_allowed_tokens(app.config) == ["valid1", "valid2"]


def test_get_allowed_tokens_empty_when_not_set(app):
    with set_config(app, AUTH_TOKENS=None):
        assert get_allowed_tokens(app.config) == []


def test_get_token_from_headers(app):
    with app.test_request_context(headers={"Authorization": "Bearer token-value"}):
        assert get_token_from_headers() == "token-value"


def test_get_token_without_bearer_auth(app):
    with app.test_request_context(headers={"Authorization": "Basic token-value"}):
        assert get_token_from_headers() is None


def test_get_token_from_empty_headers(app):
    with app.test_request_context(headers={}):
        assert get_token_from_headers() is None


def test_check_auth(mocker):
    mocker.patch("app.utils.authentication.get_token_from_headers", return_value="test-token")
    abort = mocker.patch("app.utils.authentication.abort")

    check_auth()

    assert not abort.called


def test_check_auth_without_auth_token(mocker):
    mocker.patch("app.utils.authentication.get_token_from_headers", return_value=None)
    abort = mocker.patch("app.utils.authentication.abort")

    check_auth()

    abort.assert_called_once_with(401, mock.ANY)


def test_check_auth_with_invalid_auth_token(mocker):
    mocker.patch("app.utils.authentication.get_token_from_headers", return_value="invalid")
    abort = mocker.patch("app.utils.authentication.abort")

    check_auth()

    abort.assert_called_once_with(403, mock.ANY)


def test_requires_auth(mocker):
    check_auth = mocker.patch("app.utils.authentication.check_auth")

    requires_auth(lambda: check_auth.assert_called_once_with())()
