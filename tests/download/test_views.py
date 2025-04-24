import io
from unittest import mock
from uuid import UUID

import pytest
from flask import redirect, url_for
from flask.sessions import SecureCookieSessionInterface

from app.download.views import get_redirect_url_if_user_not_authenticated
from app.utils.signed_data import sign_service_and_document_id
from app.utils.store import DocumentNotFound, DocumentStoreError


@pytest.fixture
def store(mocker):
    return mocker.patch(
        "app.download.views.document_store",
        # prevent LocalProxy being detected as an async function
        new_callable=mocker.MagicMock,
    )


def test_download_document(client, store):
    store.get.return_value = {
        "body": io.BytesIO(b"PDF document contents"),
        "mimetype": "application/pdf",
        "size": 100,
        "metadata": {},
    }

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
        "Content-Disposition": "inline; filename=ffffffff-ffff-ffff-ffff-ffffffffffff.pdf",
        "Referrer-Policy": "no-referrer",
        "X-B3-SpanId": mock.ANY,
        "X-B3-TraceId": mock.ANY,
        "X-Robots-Tag": "noindex, nofollow",
    }
    store.get.assert_called_once_with(
        UUID("00000000-0000-0000-0000-000000000000"), UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"), bytes(32)
    )


def test_download_document_with_authenticated_user(client, store):
    store.get.return_value = {
        "body": io.BytesIO(b"PDF document contents"),
        "mimetype": "application/pdf",
        "size": 100,
        "metadata": {"hashed-recipient-email": "foo bar baz"},
    }

    service_id = UUID("00000000-0000-0000-0000-000000000000")
    document_id = UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
    signed_data = sign_service_and_document_id(service_id, document_id)

    client.set_cookie(
        key="document_access_signed_data",
        value=signed_data,
        domain="localhost",
        path="/",
        httponly=True,
    )

    response = client.get(
        url_for(
            "download.download_document",
            service_id=service_id,
            document_id=document_id,
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32 \x00 bytes
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b"PDF document contents"
    store.get.assert_called_once_with(service_id, document_id, bytes(32))


@pytest.mark.parametrize(
    "mimetype, expected_extension, expected_content_type_header",
    [
        ("text/csv", "csv", "text/csv; charset=utf-8"),
        ("text/rtf", "rtf", "text/rtf; charset=utf-8"),
        ("text/plain", "txt", "text/plain; charset=utf-8"),
        ("application/rtf", "rtf", "application/rtf"),
    ],
)
def test_download_document_sets_content_type_and_disposition(
    client, store, mimetype, expected_extension, expected_content_type_header
):
    """
    Test that file responses have the expected Content-Type/Content-Disposition
    required for browsers to download files in a way that is useful for users.
    """
    store.get.return_value = {"body": io.BytesIO(b"a,b,c"), "mimetype": mimetype, "size": 100, "metadata": {}}

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
    assert response.headers["Content-Type"] == expected_content_type_header
    assert response.headers["Content-Disposition"] == f"attachment; filename={document_id}.{expected_extension}"


def test_download_document_sets_filename_from_metadata(client, store):
    """
    Test that file responses have the expected Content-Type/Content-Disposition
    required for browsers to download files in a way that is useful for users.
    """
    store.get.return_value = {
        "body": io.BytesIO(b"a,b,c"),
        "mimetype": "application/pdf",
        "size": 100,
        "metadata": {"filename": "my-nice-filename.pdf"},
    }

    document_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id=document_id,
            filename="my-nice-filename",
            extension="pdf",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32 \x00 bytes
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b"a,b,c"
    assert response.headers["Content-Type"] == "application/pdf"
    assert response.headers["Content-Disposition"] == "inline; filename=my-nice-filename.pdf"


def test_download_document_with_extension(client, store):
    store.get.return_value = {"body": io.BytesIO(b"a,b,c"), "mimetype": "application/pdf", "size": 100, "metadata": {}}

    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32 \x00 bytes
            extension="pdf",
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b"a,b,c"
    assert dict(response.headers) == {
        "Cache-Control": mock.ANY,
        "Date": mock.ANY,
        "Content-Length": "100",
        "Content-Type": "application/pdf",
        "Content-Disposition": "inline; filename=ffffffff-ffff-ffff-ffff-ffffffffffff.pdf",
        "Referrer-Policy": "no-referrer",
        "X-B3-SpanId": mock.ANY,
        "X-B3-TraceId": mock.ANY,
        "X-Robots-Tag": "noindex, nofollow",
    }


def test_download_document_without_decryption_key(client, store):
    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "Missing decryption key"}


def test_download_document_with_invalid_decryption_key(client):
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


def test_download_document_document_store_error(client, store):
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


def test_download_document_redirects_if_user_not_authenticated(client, store, mocker):
    mock_redirect_check = mocker.patch(
        "app.download.views.get_redirect_url_if_user_not_authenticated", return_value=redirect("/foo")
    )
    store.get.return_value = {"body": io.BytesIO(b"a,b,c"), "mimetype": "application/pdf", "size": 100, "metadata": {}}

    response = client.get(
        url_for(
            "download.download_document",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32 \x00 bytes
        )
    )

    assert response.status_code == 302
    assert response.location == "/foo"
    mock_redirect_check.assert_called_once()


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


@pytest.mark.parametrize(
    "mimetype, expected_extension",
    [
        ("text/csv", "csv"),
        ("application/msword", "doc"),
        ("application/pdf", "pdf"),
    ],
)
def test_get_document_metadata_when_document_is_in_s3(client, store, mimetype, expected_extension):
    store.get_document_metadata.return_value = {
        "mimetype": mimetype,
        "confirm_email": False,
        "size": 1024,
        "available_until": "2020-04-30",
        "filename": None,
    }
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
                    "http://download.document-download-frontend-test",
                    "/services/00000000-0000-0000-0000-000000000000",
                    f"/documents/ffffffff-ffff-ffff-ffff-ffffffffffff.{expected_extension}",
                    "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ]
            ),
            "confirm_email": False,
            "size_in_bytes": 1024,
            "file_extension": expected_extension,
            "available_until": "2020-04-30",
            "filename": None,
        }
    }


def test_get_document_metadata_when_document_is_not_in_s3(client, store):
    store.get_document_metadata.side_effect = DocumentNotFound("no such document")
    response = client.get(
        url_for(
            "download.get_document_metadata",
            service_id="00000000-0000-0000-0000-000000000000",
            document_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
    )

    assert response.status_code == 404
    assert response.json == {"error": "no such document"}


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
            "filename": None,
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
            "http://download.document-download-frontend-test/"
            "services/00000000-0000-0000-0000-000000000000/"
            "documents/ffffffff-ffff-ffff-ffff-ffffffffffff.csv"
            "?key=sP09NZwxDwl3DE2j1bj0jCTbBjpeLkGiJ_rq788NWHM"
        )

        signer = SecureCookieSessionInterface().get_signing_serializer(app)
        data = signer.loads(signed_data)

        assert data["service_id"] == UUID("00000000-0000-0000-0000-000000000000")
        assert data["document_id"] == UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")

    def test_authentication_rate_limiting(self, app, client, store):
        store.get_document_metadata.return_value = {
            "mimetype": "text/csv",
            "verify_email": True,
            "filename": None,
        }

        with (
            mock.patch("app.download.views.document_store.authenticate") as authenticate_mock,
            mock.patch("app.redis_client.exceeded_rate_limit") as mock_exceeded_rate_limit,
        ):
            authenticate_mock.return_value = True
            mock_exceeded_rate_limit.return_value = True

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

        assert response.status_code == 429


class TestGetRedirectUrlIfUserNotAuthenticated:
    @pytest.fixture
    def mock_doc_store_get_response(self):
        yield {
            "body": io.BytesIO(b"a,b,c"),
            "mimetype": "application/pdf",
            "size": 100,
            "metadata": {"hashed-recipient-email": "foo"},
        }

    @pytest.fixture
    def mock_request(self, client, mocker):
        mock_request = mocker.patch("app.download.views.request")
        mock_request.view_args = {
            "service_id": "00000000-0000-0000-0000-000000000000",
            "document_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        }
        mock_request.args = {"key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        mock_request.cookies = {"document_access_signed_data": "foo bar baz"}
        yield mock_request

    def test_it_returns_none_if_document_not_secured(self, mocker, mock_request, mock_doc_store_get_response):
        mock_verify = mocker.patch("app.download.views.verify_signed_service_and_document_id")
        mock_doc_store_get_response["metadata"] = {}
        mock_request.cookies = {}

        assert get_redirect_url_if_user_not_authenticated(mock_request, mock_doc_store_get_response) is None
        assert mock_verify.called is False

    def test_it_returns_none_if_signed_data_matches(self, mocker, mock_request, mock_doc_store_get_response):
        mock_verify = mocker.patch("app.download.views.verify_signed_service_and_document_id", return_value=True)

        assert get_redirect_url_if_user_not_authenticated(mock_request, mock_doc_store_get_response) is None
        mock_verify.assert_called_once_with(
            "foo bar baz", "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"
        )

    def test_it_redirects_if_signed_data_does_not_match(self, mocker, mock_request, mock_doc_store_get_response):
        mock_verify = mocker.patch("app.download.views.verify_signed_service_and_document_id", return_value=False)

        redirect = get_redirect_url_if_user_not_authenticated(mock_request, mock_doc_store_get_response)
        assert redirect.location == "".join(
            [
                "http://document-download-frontend-test",
                "/d/AAAAAAAAAAAAAAAAAAAAAA",
                "/_____________________w",
                "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ]
        )
        mock_verify.assert_called_once_with(
            "foo bar baz", "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"
        )

    def test_it_redirects_if_cookie_not_set(self, mock_request, mock_doc_store_get_response):
        mock_request.cookies = {}
        redirect = get_redirect_url_if_user_not_authenticated(mock_request, mock_doc_store_get_response)
        assert redirect.location == "".join(
            [
                "http://document-download-frontend-test",
                "/d/AAAAAAAAAAAAAAAAAAAAAA",
                "/_____________________w",
                "?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ]
        )
