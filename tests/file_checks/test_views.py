import base64

import pytest
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError


def _file_checks(client, file_content):
    url = "/antivirus_and_mimetype_check"
    data = {
        "document": base64.b64encode(file_content).decode("utf-8"),
    }
    response = client.post(url, json=data)
    return response


@pytest.fixture
def antivirus(mocker):
    return mocker.patch(
        "app.file_checks.views.antivirus_client",
        # prevent LocalProxy being detected as an async function
        new_callable=mocker.MagicMock,
    )


def test_file_checks_virus_found(client, antivirus):
    antivirus.scan.return_value = False

    file_content = b"%PDF-1.4 file contents"
    response = _file_checks(client, file_content)

    assert response.status_code == 400
    assert response.json == {"error": "File did not pass the virus scan"}


def test_file_checks_returns_json_object_with_expected_results(client, antivirus):
    antivirus.scan.return_value = True
    file_content = b"%PDF-1.4 file contents"
    response = _file_checks(client, file_content)
    assert response.status_code == 200
    assert response.json == {"mimetype": "application/pdf", "virus_free": True}


def test_file_checks_virus_scan_error(client, antivirus):
    antivirus.scan.side_effect = AntivirusError(503, "connection error")

    file_content = b"%PDF-1.4 file contents"
    response = _file_checks(client, file_content)

    assert response.status_code == 503
    assert response.json == {"error": "Antivirus API error"}


def test_file_checks_invalid_encoding(client):
    response = client.post("/antivirus_and_mimetype_check", json={"document": "foo"})

    assert response.status_code == 400
    assert response.json == {"error": "Document is not base64 encoded"}


def test_file_checks_unknown_type(client, antivirus):
    file_content = b"\x00pdf file contents\n"

    response = _file_checks(client, file_content)

    assert response.status_code == 400
    assert response.json["error"] == (
        "Unsupported file type 'application/octet-stream'. "
        "Supported types are: '.csv', '.doc', '.docx', '.jpeg', '.jpg', '.json', '.odt', '.pdf', '.png', '.rtf', "
        "'.txt', '.xlsx'"
    )
