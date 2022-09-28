from freezegun import freeze_time

from app.utils.signed_data import (
    sign_service_and_document_id,
    verify_signed_service_and_document_id,
)
from tests.conftest import set_config


def test_sign_service_and_document_id_can_be_verified(app):
    ret = sign_service_and_document_id("foo", "bar")
    assert verify_signed_service_and_document_id(ret, "foo", "bar") is True


def test_verify_signed_service_and_document_id_returns_false_if_service_and_document_id_dont_match(app):
    ret = sign_service_and_document_id("baz", "waz")
    assert verify_signed_service_and_document_id(ret, "foo", "bar") is False


def test_verify_signed_service_and_document_id_returns_false_with_old_data(app):
    with freeze_time("2020-01-01 12:00:00"):
        ret = sign_service_and_document_id("foo", "bar")
    with freeze_time("2020-01-31 11:00:00"):
        assert verify_signed_service_and_document_id(ret, "foo", "bar") is True
    with freeze_time("2020-01-31 13:00:00"):
        assert verify_signed_service_and_document_id(ret, "foo", "bar") is False


def test_verify_signed_service_and_document_id_returns_false_with_malicious_data(app):
    with set_config(app, SECRET_KEY="other value"):
        ret = sign_service_and_document_id("foo", "bar")

    assert verify_signed_service_and_document_id(ret, "foo", "bar") is False
