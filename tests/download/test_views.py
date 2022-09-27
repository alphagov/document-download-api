import io
from unittest import mock
from uuid import UUID

import pytest
from flask import url_for
from flask.sessions import SecureCookieSessionInterface

from app.utils.store import DocumentStoreError


@pytest.fixture
def store(mocker):
    return mocker.patch("app.download.views.document_store")


def test_document_download(client, store):
    store.get.return_value = {"body": io.BytesIO(b"PDF document contents"), "mimetype": "application/pdf", "size": 100}

    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32 \x00 bytes
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b"PDF document contents"
    assert dict(response.headers) == {
        "Cache-Control": mock.ANY,
        "Date": mock.ANY,
        "Content-Length": "100",
        "Content-Type": "application/pdf",
        "Referrer-Policy": "no-referrer",
        "X-B3-SpanId": "None",
        "X-B3-TraceId": "None",
        "X-Robots-Tag": "noindex, nofollow",
    }
    store.get.assert_called_once_with(
        UUID("00000000-0000-0000-0000-000000000000"), UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"), bytes(32)
    )


@pytest.mark.parametrize(
    "mimetype, expected_extension, expected_content_type_header",
    [
        ("text/csv", "csv", "text/csv; charset=utf-8"),
        ("text/rtf", "rtf", "text/rtf; charset=utf-8"),
        ("application/rtf", "rtf", "application/rtf"),
    ],
)
def test_force_document_download(client, store, mimetype, expected_extension, expected_content_type_header):
    """
    Test that file responses have the expected Content-Type/Content-Disposition
    required for browsers to download files in a way that is useful for users.
    """
    store.get.return_value = {"body": io.BytesIO(b"a,b,c"), "mimetype": mimetype, "size": 100}

    document_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id=document_id,
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32 \x00 bytes
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b"a,b,c"
    assert dict(response.headers) == {
        "Cache-Control": mock.ANY,
        "Date": mock.ANY,
        "Content-Length": "100",
        "Content-Type": expected_content_type_header,
        "Content-Disposition": f"attachment; filename={document_id}.{expected_extension}",
        "Referrer-Policy": "no-referrer",
        "X-B3-SpanId": "None",
        "X-B3-TraceId": "None",
        "X-Robots-Tag": "noindex, nofollow",
    }
    store.get.assert_called_once_with(
        UUID("00000000-0000-0000-0000-000000000000"), UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"), bytes(32)
    )


def test_document_download_with_extension(client, store):
    store.get.return_value = {"body": io.BytesIO(b"a,b,c"), "mimetype": "application/pdf", "size": 100}

    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32 \x00 bytes
            extension=".pdf",
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b"a,b,c"
    assert dict(response.headers) == {
        "Cache-Control": mock.ANY,
        "Date": mock.ANY,
        "Content-Length": "100",
        "Content-Type": "application/pdf",
        "Referrer-Policy": "no-referrer",
        "X-B3-SpanId": "None",
        "X-B3-TraceId": "None",
        "X-Robots-Tag": "noindex, nofollow",
    }


def test_document_download_without_decryption_key(client, store):
    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "Missing decryption key"}


def test_document_download_with_invalid_decryption_key(client):
    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?",
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "Invalid decryption key"}


def test_document_download_document_store_error(client, store):
    store.get.side_effect = DocumentStoreError("something went wrong")
    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "something went wrong"}


def test_get_document_metadata_without_decryption_key(client, store):
    response = client.get(
        url_for(
            "download.get_document_metadata",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "Missing decryption key"}


def test_get_document_metadata_with_invalid_decryption_key(client):
    response = client.get(
        url_for(
            "download.get_document_metadata",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?",
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "Invalid decryption key"}


def test_get_document_metadata_document_store_error(client, store):
    store.get_document_metadata.side_effect = DocumentStoreError("something went wrong")
    response = client.get(
        url_for(
            "download.get_document_metadata",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "something went wrong"}


def test_get_document_metadata_when_document_is_in_s3(client, store):
    store.get_document_metadata.return_value = {"mimetype": "text/plain", "confirm_email": False, "size": 1024}
    response = client.get(
        url_for(
            "download.get_document_metadata",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
    )

    assert response.status_code == 200
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"
    assert response.json == {
        "document": {
            "direct_file_url": "".join(
                [
                    "http://document-download.test",
                    "/services/00000000-0000-0000-0000-000000000000",
                    "/documents/ffffffff-ffff-ffff-ffff-ffffffffffff.txt",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
            "confirm_email": False,
            "size_in_bytes": 1024,
        }
    }


def test_get_document_metadata_when_document_is_not_in_s3(client, store):
    store.get_document_metadata.return_value = None
    response = client.get(
        url_for(
            "download.get_document_metadata",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
    )

    assert response.status_code == 200
    assert response.json == {"document": None}
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"


class TestAuthenticateDocument:
    def test_missing_decryption_key(self, client, store):
        response = client.post(
            url_for(
                "download.authenticate_access_to_document",
                service_id="00000000-0000-0000-0000-000000000000",
                document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
            json={
                "email_address": "bad@notify.example",
            },
        )

        assert response.status_code == 400
        assert response.json["error"] == "Missing decryption key"

    def test_invalid_decryption_key(self, client, store):
        response = client.post(
            url_for(
                "download.authenticate_access_to_document",
                service_id="00000000-0000-0000-0000-000000000000",
                document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
            json={
                "key": "a",
                "email_address": "bad@notify.example",
            },
        )

        assert response.status_code == 400
        assert response.json["error"] == "Invalid decryption key"

    def test_no_email_address(self, client, store):
        response = client.post(
            url_for(
                "download.authenticate_access_to_document",
                service_id="00000000-0000-0000-0000-000000000000",
                document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
            json={
                "key": "sP09NZwxDwl3DE2j1bj0jCTbBjpeLkGiJ_rq788NWHM",  # bytes_to_Base64(os.urandom(32))
            },
        )

        assert response.status_code == 400
        assert response.json["error"] == "No email address"

    def test_invalid_email_address(self, client, store):
        response = client.post(
            url_for(
                "download.authenticate_access_to_document",
                service_id="00000000-0000-0000-0000-000000000000",
                document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
            json={
                "key": "sP09NZwxDwl3DE2j1bj0jCTbBjpeLkGiJ_rq788NWHM",  # bytes_to_Base64(os.urandom(32))
                "email_address": "not-an-email",
            },
        )

        assert response.status_code == 400
        assert response.json["error"] == "Invalid email address"

    def test_authentication_failure(self, client, store):
        with mock.patch("app.download.views.document_store.authenticate") as authenticate_mock:
            authenticate_mock.return_value = False

            response = client.post(
                url_for(
                    "download.authenticate_access_to_document",
                    service_id="00000000-0000-0000-0000-000000000000",
                    document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
                ),
                json={
                    "key": "sP09NZwxDwl3DE2j1bj0jCTbBjpeLkGiJ_rq788NWHM",  # bytes_to_Base64(os.urandom(32))
                    "email_address": "test@notify.example",
                },
            )

        assert response.status_code == 403
        assert response.json["error"] == "Authentication failure"

    def test_signed_data_from_successful_authentication(self, app, client, store):
        store.get_document_metadata.return_value = {
            "mimetype": "text/csv",
            "confirm_email": True,
        }

        with mock.patch("app.download.views.document_store.authenticate") as authenticate_mock:
            authenticate_mock.return_value = True

            response = client.post(
                url_for(
                    "download.authenticate_access_to_document",
                    service_id="00000000-0000-0000-0000-000000000000",
                    document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
                ),
                json={
                    "key": "sP09NZwxDwl3DE2j1bj0jCTbBjpeLkGiJ_rq788NWHM",  # bytes_to_Base64(os.urandom(32))
                    "email_address": "test@notify.example",
                },
            )
            signed_data = response.json["signed_data"]
            direct_file_url = response.json["direct_file_url"]

        assert response.status_code == 200
        assert direct_file_url == (
            "http://document-download.test/"
            "services/00000000-0000-0000-0000-000000000000/"
            "documents/ffffffff-ffff-ffff-ffff-ffffffffffff.csv"
            "?key=sP09NZwxDwl3DE2j1bj0jCTbBjpeLkGiJ_rq788NWHM"
        )

        signer = SecureCookieSessionInterface().get_signing_serializer(app)
        data = signer.loads(signed_data)

        assert data["service_id"] == UUID("00000000-0000-0000-0000-000000000000")
        assert data["document_id"] == UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
