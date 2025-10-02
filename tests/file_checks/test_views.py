import base64
from unittest.mock import call
from uuid import UUID

import pytest
from flask import current_app
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError

from app.config import Test


def _file_checks(client, file_content, is_csv=None, filename=None, service_id=None):
    service_id = service_id or UUID(int=0, version=4)
    url = f"/services/{service_id}/antivirus-and-mimetype-check"
    data = {
        "document": base64.b64encode(file_content).decode("utf-8"),
    }
    if is_csv is not None:
        data |= {"is_csv": is_csv}
    if filename is not None:
        data |= {"filename": filename}
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
    assert response.json == {"mimetype": "application/pdf"}


def test_file_checks_virus_scan_error(client, antivirus):
    antivirus.scan.side_effect = AntivirusError(503, "connection error")

    file_content = b"%PDF-1.4 file contents"
    response = _file_checks(client, file_content)

    assert response.status_code == 503
    assert response.json == {"error": "Antivirus API error"}


def test_file_checks_invalid_encoding(client):
    service_id = UUID(int=0, version=4)
    response = client.post(f"/services/{service_id}/antivirus-and-mimetype-check", json={"document": "foo"})

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


@pytest.mark.parametrize(
    "antivirus_scan_result, expected_first_cache_value, expected_second_cache_value",
    (
        (
            True,
            '{"success": {"mimetype": "application/pdf"}}',
            '{"success": {"mimetype": "text/plain"}}',
        ),
        (
            False,
            '{"failure": {"error": "File did not pass the virus scan", "status_code": 400}}',
            '{"failure": {"error": "File did not pass the virus scan", "status_code": 400}}',
        ),
    ),
)
def test_virus_check_puts_value_in_cache(
    client,
    mocker,
    antivirus,
    antivirus_scan_result,
    expected_first_cache_value,
    expected_second_cache_value,
):
    antivirus.scan.return_value = antivirus_scan_result
    mock_redis_set = mocker.patch("app.redis_client.set")

    _file_checks(client, b"%PDF-1.4 first file contents")
    _file_checks(client, b"second file contents")

    assert mock_redis_set.call_args_list == [
        call(
            "file-checks-78b2a017d57195bd248ea2ac7ca7c676ff082ae9",
            expected_first_cache_value,
            ex=86_400,
        ),
        call(
            "file-checks-b9e8a7de077339594399102403d2834b21324613",
            expected_second_cache_value,
            ex=86_400,
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

    assert len(mock_redis_get.call_args_list) == 6
    assert len({c[0] for c in mock_redis_get.call_args_list}) == 2


def test_different_cache_keys_for_different_service_ids(client, mocker):
    mock_redis_get = mocker.patch(
        "app.redis_client.get",
        return_value='{"failure": {"error": "I’m a teapot", "status_code": 418}}'.encode(),
    )

    file_content = b"%PDF-1.4 file contents"

    _file_checks(client, file_content, service_id=UUID(int=0, version=4))
    _file_checks(client, file_content, service_id=UUID(int=1, version=4))
    _file_checks(client, file_content, service_id=UUID(int=1, version=4))

    assert len(mock_redis_get.call_args_list) == 3
    assert len({c[0] for c in mock_redis_get.call_args_list}) == 2


def test_different_cache_keys_for_different_filename_and_is_csv(client, mocker):
    mock_redis_get = mocker.patch(
        "app.redis_client.get",
        return_value='{"failure": {"error": "I’m a teapot", "status_code": 418}}'.encode(),
    )

    file_content = b"%PDF-1.4 first file contents"

    _file_checks(client, file_content)
    _file_checks(client, file_content, filename="foo.pdf")
    _file_checks(client, file_content, filename="bar.pdf")
    _file_checks(client, file_content, filename="bar.jpg")
    _file_checks(client, file_content, filename="bar.jpg", is_csv=True)
    _file_checks(client, file_content, is_csv=True)

    assert mock_redis_get.call_args_list == [
        # No filename
        call("file-checks-78b2a017d57195bd248ea2ac7ca7c676ff082ae9"),
        # Different filenames but same extension
        call("file-checks-01de2a8237b9fbdb364a257098787408ae53ab97"),
        call("file-checks-01de2a8237b9fbdb364a257098787408ae53ab97"),
        # Different extension
        call("file-checks-1b6950c7d6718aad287c9718771229d7c6321a99"),
        # Same filename but is_csv=True (which is ignored)
        call("file-checks-1b6950c7d6718aad287c9718771229d7c6321a99"),
        # No filename but is_csv=True
        call("file-checks-cf0768397cf40807321810280dc65d236bc53c70"),
    ]


def test_success_response_from_cache(client, mocker):
    mocker.patch(
        "app.redis_client.get",
        return_value=b'{"success": {"mimetype": "application/pdf"}}',
    )

    response = _file_checks(client, b"Anything")

    assert response.status_code == 200
    assert response.json == {"mimetype": "application/pdf"}


@pytest.mark.xdist_group(name="modifies_app_context")
@pytest.mark.parametrize(
    "scan_results",
    (
        # Scan results are ignored
        True,
        False,
    ),
)
@pytest.mark.parametrize(
    "antivirus_enabled",
    (
        pytest.param(
            True,
            marks=pytest.mark.xfail(reason="Virus scan will be called"),
        ),
        False,
    ),
)
def test_file_is_always_virus_free_when_antivirus_disabled(antivirus, client, mocker, scan_results, antivirus_enabled):
    current_app.config["ANTIVIRUS_ENABLED"] = antivirus_enabled
    antivirus.scan.return_value = scan_results

    response = _file_checks(client, b"Anything")

    assert response.status_code == 200
    assert response.json == {"mimetype": "text/plain"}
    assert antivirus.scan.called is False

    # Reset the app config to avoid affecting other tests
    current_app.config["ANTIVIRUS_ENABLED"] = Test.ANTIVIRUS_ENABLED
