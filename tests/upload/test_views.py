import base64
from pathlib import Path

import pytest
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError

import app
from app.upload.views import UploadedFile
from app.utils.file_checks import AntivirusAndMimeTypeCheckError


@pytest.fixture
def store(mocker):
    return mocker.patch(
        "app.upload.views.document_store",
        # prevent LocalProxy being detected as an async function
        new_callable=mocker.MagicMock,
    )


@pytest.fixture
def antivirus(mocker):
    return mocker.patch(
        "app.utils.file_checks.antivirus_client",
        # prevent LocalProxy being detected as an async function
        new_callable=mocker.MagicMock,
    )


def _document_upload(client, url, file_content, confirmation_email=None, retention_period=None):
    data = {
        "document": base64.b64encode(file_content).decode("utf-8"),
    }

    if confirmation_email:
        data["confirmation_email"] = confirmation_email
    if retention_period:
        data["retention_period"] = retention_period

    response = client.post(url, json=data)
    return response


def test_document_upload_returns_link_to_frontend(client, store, antivirus):
    store.put.return_value = {
        "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "encryption_key": bytes(32),
    }

    antivirus.scan.return_value = True

    url = "/services/00000000-0000-0000-0000-000000000000/documents"
    file_content = b"%PDF-1.4 file contents"
    response = _document_upload(client, url, file_content)

    # Check that the contents of the file saved is as expected
    put_args, put_kwargs = store.put.call_args_list[0]
    saved_file = put_args[1]
    assert saved_file.read() == file_content

    assert response.status_code == 201
    assert response.json == {
        "document": {
            "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "url": "".join(
                [
                    "http://document-download-frontend-test",
                    "/d/AAAAAAAAAAAAAAAAAAAAAA",
                    "/_____________________w",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
            "direct_file_url": "".join(
                [
                    "http://download.document-download-frontend-test",
                    "/services/00000000-0000-0000-0000-000000000000",
                    "/documents/ffffffff-ffff-ffff-ffff-ffffffffffff.pdf",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
            "mimetype": "application/pdf",
        },
        "status": "ok",
    }


def test_document_upload_sends_confirmation_email_on_to_document_store(client, store, antivirus):
    store.put.return_value = {
        "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "encryption_key": bytes(32),
    }

    antivirus.scan.return_value = True

    url = "/services/00000000-0000-0000-0000-000000000000/documents"
    file_content = b"%PDF-1.4 file contents"
    _document_upload(client, url, file_content, confirmation_email="user@example.com")

    # Check that the contents of the file saved is as expected
    put_args, put_kwargs = store.put.call_args_list[0]

    assert put_kwargs["confirmation_email"] == "user@example.com"


def test_document_upload_virus_found(client, store, antivirus):
    antivirus.scan.return_value = False

    url = "/services/12345678-1111-1111-1111-123456789012/documents"
    file_content = b"%PDF-1.4 file contents"
    response = _document_upload(client, url, file_content)

    assert response.status_code == 400
    assert response.json == {"error": "File did not pass the virus scan"}


def test_document_upload_virus_scan_error(client, store, antivirus):
    antivirus.scan.side_effect = AntivirusError(503, "connection error")

    url = "/services/12345678-1111-1111-1111-123456789012/documents"
    file_content = b"%PDF-1.4 file contents"
    response = _document_upload(client, url, file_content)

    assert response.status_code == 503
    assert response.json == {"error": "Antivirus API error"}


def test_document_upload_invalid_encoding(client):
    response = client.post("/services/12345678-1111-1111-1111-123456789012/documents", json={"document": "foo"})

    assert response.status_code == 400
    assert response.json == {"error": "Document is not base64 encoded"}


def test_document_upload_unknown_type(client, antivirus):
    url = "/services/12345678-1111-1111-1111-123456789012/documents"
    file_content = b"\x00pdf file contents\n"

    response = _document_upload(client, url, file_content)

    assert response.status_code == 400
    assert response.json["error"] == (
        "Unsupported file type 'application/octet-stream'. "
        "Supported types are: '.csv', '.doc', '.docx', '.jpeg', '.jpg', '.json', '.odt', '.pdf', '.png', '.rtf', "
        "'.txt', '.xlsx'"
    )


def test_document_file_size_just_right_after_b64decode(client, store, antivirus):
    store.put.return_value = {
        "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "encryption_key": bytes(32),
    }

    antivirus.scan.return_value = True

    url = "/services/12345678-1111-1111-1111-123456789012/documents"
    file_content = b"%PDF-1.5 " + b"a" * (2 * 1024 * 1024 - 9)
    response = _document_upload(client, url, file_content)

    assert response.status_code == 201


@pytest.mark.parametrize(
    "file_size_in_bytes, application_code_call_expected",
    (
        # Gets hit by Werkzeug's 3MiB content length limit automatically (before our app logic).
        ((3 * 1024 * 1024 + 1), False),
        # Gets through Werkzeug's 3MiB content length limit, but too big for our python ~2MiB check.
        ((2 * 1024 * 1024 + 1025), True),
    ),
)
def test_document_file_size_too_large(client, mocker, file_size_in_bytes, application_code_call_expected):
    mock_uploaded_file = mocker.patch(
        "app.upload.views.UploadedFile.from_request_json", wraps=UploadedFile.from_request_json
    )
    url = "/services/12345678-1111-1111-1111-123456789012/documents"

    file_content = b"a" * file_size_in_bytes
    response = _document_upload(client, url, file_content)

    assert response.status_code == 413
    assert response.json == {"error": "Uploaded file exceeds file size limit"}
    assert mock_uploaded_file.called is application_code_call_expected


def test_document_upload_no_document(client):
    response = client.post(
        "/services/12345678-1111-1111-1111-123456789012/documents",
        json={
            "file": base64.b64encode(b"%PDF-1.4 file contents").decode("utf-8"),
        },
    )

    assert response.status_code == 400


def test_unauthorized_document_upload(client):
    response = client.post(
        "/services/12345678-1111-1111-1111-123456789012/documents",
        json={
            "document": base64.b64encode(b"%PDF-1.4 file contents").decode("utf-8"),
        },
        headers={
            "Authorization": None,
        },
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "file_name,extra_form_data,expected_mimetype",
    (
        (
            "test.csv",
            {"is_csv": True},
            "text/csv",
        ),
        (
            "test.csv",
            {"is_csv": False},
            "text/plain",
        ),
        (
            "test.csv",
            {},
            "text/plain",
        ),
        (
            "test_longer.csv",
            {"is_csv": True},
            "text/csv",
        ),
        (
            "test_longer.csv",
            {"is_csv": False},
            "text/csv",
        ),
        (
            "test_longer.csv",
            {},
            "text/csv",
        ),
        (
            "test.txt",
            {"is_csv": True},
            "text/csv",
        ),
        (
            "test.txt",
            {"is_csv": False},
            "text/plain",
        ),
        (
            "test.txt",
            {},
            "text/plain",
        ),
        (
            "test.pdf",
            {"is_csv": True},
            "application/pdf",
        ),
        (
            "test.pdf",
            {"is_csv": False},
            "application/pdf",
        ),
        (
            "test.pdf",
            {},
            "application/pdf",
        ),
    ),
)
def test_document_upload_csv_handling(
    app,
    client,
    store,
    antivirus,
    file_name,
    extra_form_data,
    expected_mimetype,
):
    store.put.return_value = {
        "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "encryption_key": bytes(32),
    }

    antivirus.scan.return_value = True

    with open(Path(__file__).parent.parent / "sample_files" / file_name, "rb") as f:
        response = client.post(
            "/services/00000000-0000-0000-0000-000000000000/documents",
            json={
                "document": base64.b64encode(f.read()).decode("utf-8"),
                **extra_form_data,
            },
        )

    assert response.status_code == 201
    assert response.json == {
        "document": {
            "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "url": "".join(
                [
                    "http://document-download-frontend-test",
                    "/d/AAAAAAAAAAAAAAAAAAAAAA",
                    "/_____________________w",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
            "mimetype": expected_mimetype,
            "direct_file_url": "".join(
                [
                    "http://download.document-download-frontend-test",
                    "/services/00000000-0000-0000-0000-000000000000",
                    "/documents/ffffffff-ffff-ffff-ffff-ffffffffffff",
                    f".{app.config['MIME_TYPES_TO_FILE_EXTENSIONS'][expected_mimetype]}",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
        },
        "status": "ok",
    }


@pytest.mark.parametrize("extension, expected_mimetype", app.config.Config.FILE_EXTENSIONS_TO_MIMETYPES.items())
@pytest.mark.parametrize("is_csv", (True, False))  # `is_csv` should just be ignored when `filename` is provided
def test_document_upload_filename_handling(
    app,
    client,
    store,
    antivirus,
    expected_mimetype,
    extension,
    is_csv,
):
    store.put.return_value = {
        "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "encryption_key": bytes(32),
    }

    antivirus.scan.return_value = True

    file_name = f"test-file.{extension}"
    with open(Path(__file__).parent.parent / "sample_files" / f"test.{extension}", "rb") as f:
        response = client.post(
            "/services/00000000-0000-0000-0000-000000000000/documents",
            json={
                "document": base64.b64encode(f.read()).decode("utf-8"),
                "filename": file_name,
                "is_csv": is_csv,
            },
        )

    assert response.status_code == 201

    if extension == "jpg":
        extension = "jpeg"  # for .jpg we automatically change extension to .jpeg
    assert response.json == {
        "document": {
            "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "url": "".join(
                [
                    "http://document-download-frontend-test",
                    "/d/AAAAAAAAAAAAAAAAAAAAAA",
                    "/_____________________w",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
            "mimetype": expected_mimetype,
            "direct_file_url": "".join(
                [
                    "http://download.document-download-frontend-test",
                    "/services/00000000-0000-0000-0000-000000000000",
                    "/documents/ffffffff-ffff-ffff-ffff-ffffffffffff",
                    f".{extension}",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
        },
        "status": "ok",
    }


def test_document_upload_bad_is_csv_value(client):
    with open(Path(__file__).parent.parent / "sample_files" / "test.csv", "rb") as f:
        response = client.post(
            "/services/00000000-0000-0000-0000-000000000000/documents",
            json={
                "document": base64.b64encode(f.read()).decode("utf-8"),
                "is_csv": "Foobar",
            },
        )

    assert response.status_code == 400
    assert response.json == {"error": "Value for is_csv must be a boolean"}


@pytest.mark.parametrize(
    "data, expected_error",
    (
        ({}, "No document upload"),
        ({"document": "foo"}, "Document is not base64 encoded"),
        ({"document": "😇"}, "Document is not base64 encoded"),
        ({"document": "YQoxLAo=", "is_csv": 1}, "Value for is_csv must be a boolean"),
        ({"document": "YQoxLAo=", "confirmation_email": True}, "Confirmation email must be a string."),
        ({"document": "YQoxLAo=", "confirmation_email": "sam@foo"}, "Not a valid email address"),
        (
            {"document": "YQoxLAo=", "retention_period": True},
            "Retention period must be a string of the format '<1-78> weeks'.",
        ),
        (
            {"document": "YQoxLAo=", "retention_period": "3 days"},
            "Retention period must be a string of the format '<1-78> weeks'.",
        ),
        (
            {"document": "YQoxLAo=", "filename": "no file extension"},
            "`filename` must end with a file extension. For example, filename.csv",
        ),
        (
            {"document": "YQoxLAo=", "filename": "rejected-file-extension.gif"},
            (
                "Unsupported file type '.gif'. "
                "Supported types are: '.csv', '.doc', '.docx', '.jpeg', '.jpg', '.json', '.odt', '.pdf', '.png',"
                " '.rtf', '.txt', '.xlsx'"
            ),
        ),
    ),
)
def test_get_upload_document_request_data_errors(app, data, expected_error):
    with pytest.raises(AntivirusAndMimeTypeCheckError) as e:
        UploadedFile.from_request_json(data, service_id="foo")

    assert e.value.message == expected_error
