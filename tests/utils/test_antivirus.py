import io

import pytest
import requests
import requests_mock
from notifications_utils.testing.comparisons import AnySupersetOf

from app.utils.antivirus import AntivirusClient, AntivirusError
from tests.conftest import set_config


@pytest.fixture(scope="function")
def app_antivirus(app):
    client = AntivirusClient()
    with set_config(
        app,
        ANTIVIRUS_API_HOST="https://antivirus",
        ANTIVIRUS_API_KEY="test-antivirus-key",
    ):
        client.init_app(app)
        yield app, client


def test_scan_document(mocker, app_antivirus):
    app, antivirus = app_antivirus
    mocker.patch(
        "notifications_utils.request_helper.NotifyRequest.get_onwards_request_headers",
        return_value={"some-onwards": "request-header"},
    )
    document = io.BytesIO(b"filecontents")
    with requests_mock.Mocker() as request_mock:
        request_mock.post(
            "https://antivirus/scan",
            json={"ok": True},
            request_headers={
                "Authorization": "Bearer test-antivirus-key",
            },
            status_code=200,
        )

        with app.test_request_context():
            resp = antivirus.scan(document)

    assert resp
    assert len(request_mock.request_history) == 1
    assert "filecontents" in request_mock.request_history[0].text
    assert request_mock.request_history[0].headers == AnySupersetOf({"some-onwards": "request-header"})
    assert document.tell() == 0


def test_scan_document_no_req_context(app_antivirus):
    app, antivirus = app_antivirus
    document = io.BytesIO(b"filecontents")
    with requests_mock.Mocker() as request_mock:
        request_mock.post(
            "https://antivirus/scan",
            json={"ok": True},
            request_headers={
                "Authorization": "Bearer test-antivirus-key",
            },
            status_code=200,
        )

        resp = antivirus.scan(document)

    assert resp
    assert len(request_mock.request_history) == 1
    assert "filecontents" in request_mock.request_history[0].text
    assert document.tell() == 0


def test_should_raise_for_status(app_antivirus):
    app, antivirus = app_antivirus
    with pytest.raises(AntivirusError) as excinfo, requests_mock.Mocker() as request_mock:
        request_mock.post("https://antivirus/scan", json={"error": "Antivirus error"}, status_code=400)

        antivirus.scan(io.BytesIO(b"document"))

    assert excinfo.value.message == "Antivirus error"
    assert excinfo.value.status_code == 400


def test_should_raise_for_connection_errors(app_antivirus):
    app, antivirus = app_antivirus
    with pytest.raises(AntivirusError) as excinfo, requests_mock.Mocker() as request_mock:
        request_mock.post("https://antivirus/scan", exc=requests.exceptions.ConnectTimeout)

        antivirus.scan(io.BytesIO(b"document"))

    assert excinfo.value.message == "connection error"
    assert excinfo.value.status_code == 503
