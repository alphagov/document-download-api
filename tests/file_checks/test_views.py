import base64
from unittest.mock import call

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
        "app.utils.file_checks.antivirus_client",
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


def test_virus_check_puts_value_in_cache(client, mocker, antivirus):
    antivirus.scan.return_value = True
    mock_redis_set = mocker.patch("app.redis_client.set")

    _file_checks(client, b"%PDF-1.4 first file contents")
    _file_checks(client, b"second file contents")

    assert mock_redis_set.call_args_list == [
        call(
            "file-checks-d90dbad3ec3d280ac1190458b692d56661f7410a",
            '{"success": {"virus_free": true, "mimetype": "application/pdf"}}',
            ex=2419200,
        ),
        call(
            "file-checks-85336573f4f627cefb440bc2140c9a6b4925355b",
            '{"success": {"virus_free": true, "mimetype": "text/plain"}}',
            ex=2419200,
        ),
    ]


def test_virus_check_returns_value_from_cache(client, mocker):
    mock_redis_get = mocker.patch(
        "app.redis_client.get",
        return_value='{"failure": {"error": "I’m a teapot", "status_code": 418}}'.encode(),
    )

    file_1_content = b"%PDF-1.4 first file contents"
    file_2_content = b"%PDF-1.4 second file contents"

    for _ in range(3):
        response_1 = _file_checks(client, file_1_content)
        response_2 = _file_checks(client, file_2_content)

        assert response_1.status_code == response_2.status_code == 418
        assert response_1.json == response_2.json == {"error": "I’m a teapot"}

    assert mock_redis_get.call_args_list == [
        call("file-checks-d90dbad3ec3d280ac1190458b692d56661f7410a"),
        call("file-checks-93fb06037e8211f2fe7fbffe31b69ec0df48789e"),
        call("file-checks-d90dbad3ec3d280ac1190458b692d56661f7410a"),
        call("file-checks-93fb06037e8211f2fe7fbffe31b69ec0df48789e"),
        call("file-checks-d90dbad3ec3d280ac1190458b692d56661f7410a"),
        call("file-checks-93fb06037e8211f2fe7fbffe31b69ec0df48789e"),
    ]
