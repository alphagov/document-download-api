import uuid
from datetime import date
from unittest import mock

import botocore
import pytest
from botocore.exceptions import ClientError as BotoClientError

from app.utils.store import (
    DocumentBlocked,
    DocumentExpired,
    DocumentStore,
    DocumentStoreError,
)
from tests.conftest import Matcher


@pytest.fixture
def mock_boto(mocker):
    mock_boto = mocker.patch("app.utils.store.boto3")
    return mock_boto


@pytest.fixture
def store(mock_boto):
    mock_boto.client.return_value.get_object.return_value = {
        "Body": mock.Mock(),
        "ContentType": "application/pdf",
        "ContentLength": 100,
        "Metadata": {},
    }
    mock_boto.client.return_value.head_object.return_value = {
        "ResponseMetadata": {"RequestId": "ABCD"},
        "Expiration": 'expiry-date="Fri, 01 May 2020 00:00:00 GMT", expiry-rule="custom-retention-1-weeks"',
        "ContentType": "text/plain",
        "ContentLength": 100,
        "Metadata": {},
    }
    store = DocumentStore(bucket="test-bucket")
    return store


@pytest.fixture
def blocked_document(mock_boto):
    mock_boto.client.return_value.get_object_tagging.return_value = {
        "VersionId": "1",
        "TagSet": [
            {"Key": "irrelevant", "Value": "Nothing"},
            {"Key": "blocked", "Value": "true"},
        ],
    }


@pytest.fixture
def expired_document(mock_boto):
    mock_boto.client.return_value.get_object_tagging.side_effect = botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "MethodNotAllowed",
                "Message": "The specified method is not allowed against this resource.",
                "Method": "GET",
                "ResourceType": "DeleteMarker",
            }
        },
        "GetObjectTagging",
    )


@pytest.fixture
def missing_document(mock_boto):
    mock_boto.client.return_value.get_object_tagging.side_effect = botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "NoSuchKey",
                "Message": "The specified key does not exist.",
                "Key": "object-key",
            }
        },
        "GetObjectTagging",
    )


@pytest.fixture
def store_with_email(mock_boto):
    mock_boto.client.return_value.get_object.return_value = {
        "Body": mock.Mock(),
        "ContentType": "application/pdf",
        "ContentLength": 100,
        "Metadata": {
            "hashed-recipient-email": (
                # Hash of 'test@notify.example'
                "$argon2id$v=19$m=15360,t=2,p=1$ExyWUyRCJcqzJ+ip7SFZ2A$5SUu0QuYiF/kA9pdLsmE+A"
            )
        },
    }
    mock_boto.client.return_value.head_object.return_value = {
        "ResponseMetadata": {"RequestId": "ABCD"},
        "Expiration": 'expiry-date="Fri, 01 May 2020 00:00:00 GMT"',
        "ContentType": "text/plain",
        "ContentLength": 100,
        "Metadata": {
            "hashed-recipient-email": (
                # Hash of 'test@notify.example'
                "$argon2id$v=19$m=15360,t=2,p=1$ExyWUyRCJcqzJ+ip7SFZ2A$5SUu0QuYiF/kA9pdLsmE+A"
            )
        },
    }
    store = DocumentStore(bucket="test-bucket")
    return store


@pytest.fixture
def store_with_filename(mock_boto):
    mock_boto.client.return_value.get_object.return_value = {
        "Body": mock.Mock(),
        "ContentType": "application/pdf",
        "ContentLength": 100,
        "Metadata": {"filename": r"\u2705.pdf"},  # `✅.pdf` encoded for storage in AWS S3 Metadata
    }
    mock_boto.client.return_value.head_object.return_value = {
        "ResponseMetadata": {"RequestId": "ABCD"},
        "Expiration": 'expiry-date="Fri, 01 May 2020 00:00:00 GMT"',
        "ContentType": "text/plain",
        "ContentLength": 100,
        "Metadata": {"filename": r"\u2705.pdf"},  # `✅.pdf` encoded for storage in AWS S3 Metadata
    }
    store = DocumentStore(bucket="test-bucket")
    return store


def test_get_document_key(store):
    assert store.get_document_key("service-id", "doc-id") == "service-id/doc-id"


def test_document_key_with_uuid(store):
    service_id = uuid.uuid4()
    document_id = uuid.uuid4()

    assert store.get_document_key(service_id, document_id) == f"{str(service_id)}/{str(document_id)}"


@pytest.mark.parametrize(
    "blocked_value",
    (
        "True",
        "true",
        "TRUE",
        "yes",
        "YES",
        pytest.param("no", marks=pytest.mark.xfail),
        pytest.param("false", marks=pytest.mark.xfail),
        pytest.param("", marks=pytest.mark.xfail),
        pytest.param(None, marks=pytest.mark.xfail),
    ),
)
def test_check_for_blocked_document_raises_error(store, mock_boto, blocked_value):
    tags = [
        {"Key": "irrelevant", "Value": "Nothing"},
    ]
    if blocked_value is not None:
        tags.append({"Key": "blocked", "Value": blocked_value})

    mock_boto.client.return_value.get_object_tagging.return_value = {
        "VersionId": "1",
        "TagSet": tags,
    }

    with pytest.raises(DocumentBlocked):
        store.check_for_blocked_document("service-id", "doc-id")


def test_check_for_blocked_document_raises_expired_error(store, expired_document):
    with pytest.raises(DocumentExpired):
        store.check_for_blocked_document("service-id", "doc-id")


def test_check_for_blocked_document_reraises_other_boto_error(store, missing_document):
    with pytest.raises(BotoClientError):
        store.check_for_blocked_document("service-id", "doc-id")


def test_put_document(store):
    ret = store.put(
        "service-id", mock.Mock(), mimetype="application/pdf", confirmation_email=None, retention_period=None
    )

    assert ret == {
        "id": Matcher("UUID length match", lambda x: len(x) == 36),
        "encryption_key": Matcher("32 bytes", lambda x: len(x) == 32 and isinstance(x, bytes)),
    }

    store.s3.put_object.assert_called_once_with(
        Body=mock.ANY,
        Bucket="test-bucket",
        ContentType="application/pdf",
        Key=Matcher("document key", lambda x: x.startswith("service-id/") and len(x) == 11 + 36),
        SSECustomerKey=ret["encryption_key"],
        SSECustomerAlgorithm="AES256",
        Metadata={},
    )


def test_put_document_sends_hashed_recipient_email_to_s3_as_metadata_if_confirmation_email_present(store):
    ret = store.put("service-id", mock.Mock(), mimetype="application/pdf", confirmation_email="email@example.com")

    assert ret == {
        "id": Matcher("UUID length match", lambda x: len(x) == 36),
        "encryption_key": Matcher("32 bytes", lambda x: len(x) == 32 and isinstance(x, bytes)),
    }

    store.s3.put_object.assert_called_once_with(
        Body=mock.ANY,
        Bucket="test-bucket",
        ContentType="application/pdf",
        Key=Matcher("document key", lambda x: x.startswith("service-id/") and len(x) == 11 + 36),
        SSECustomerKey=ret["encryption_key"],
        SSECustomerAlgorithm="AES256",
        Metadata={"hashed-recipient-email": mock.ANY},
    )


def test_put_document_tags_document_if_retention_period_set(store):
    ret = store.put("service-id", mock.Mock(), mimetype="application/pdf", retention_period="4 weeks")

    assert ret == {
        "id": Matcher("UUID length match", lambda x: len(x) == 36),
        "encryption_key": Matcher("32 bytes", lambda x: len(x) == 32 and isinstance(x, bytes)),
    }

    store.s3.put_object.assert_called_once_with(
        Body=mock.ANY,
        Bucket="test-bucket",
        ContentType="application/pdf",
        Key=Matcher("document key", lambda x: x.startswith("service-id/") and len(x) == 11 + 36),
        SSECustomerKey=ret["encryption_key"],
        SSECustomerAlgorithm="AES256",
        Tagging="retention-period=4+weeks",
        Metadata={},
    )


@pytest.mark.parametrize(
    "filename, expected_filename_for_s3",
    (
        ("my-nice-filename.pdf", "my-nice-filename.pdf"),
        ("Юникод.pdf", r"\u042e\u043d\u0438\u043a\u043e\u0434.pdf"),
        ("✅.pdf", r"\u2705.pdf"),
        # If someone passes us a string which has some \uxxxx text (not bytes) it should be double-escaped
        (r"\u2705.pdf", r"\\u2705.pdf"),
    ),
)
def test_put_document_records_filename_if_set(store, filename, expected_filename_for_s3):
    ret = store.put("service-id", mock.Mock(), mimetype="application/pdf", filename=filename)

    assert ret == {
        "id": Matcher("UUID length match", lambda x: len(x) == 36),
        "encryption_key": Matcher("32 bytes", lambda x: len(x) == 32 and isinstance(x, bytes)),
    }

    store.s3.put_object.assert_called_once_with(
        Body=mock.ANY,
        Bucket="test-bucket",
        ContentType="application/pdf",
        Key=Matcher("document key", lambda x: x.startswith("service-id/") and len(x) == 11 + 36),
        SSECustomerKey=ret["encryption_key"],
        SSECustomerAlgorithm="AES256",
        Metadata={"filename": expected_filename_for_s3},
    )


def test_get_document(store):
    assert store.get("service-id", "document-id", bytes(32)) == {
        "body": mock.ANY,
        "mimetype": "application/pdf",
        "size": 100,
        "metadata": {},
    }

    store.s3.get_object.assert_called_once_with(
        Bucket="test-bucket",
        Key="service-id/document-id",
        SSECustomerAlgorithm="AES256",
        # 32 null bytes
        SSECustomerKey=bytes(32),
    )


def test_get_document_with_boto_error(store):
    store.s3.get_object = mock.Mock(
        side_effect=BotoClientError({"Error": {"Code": "Error code", "Message": "Error message"}}, "GetObject")
    )

    with pytest.raises(DocumentStoreError):
        store.get("service-id", "document-id", "0f0f0f")


def test_get_blocked_document(store, blocked_document):
    with pytest.raises(DocumentStoreError) as e:
        store.get("service-id", "document-id", bytes(32))

    assert str(e.value) == "Access to the document has been blocked"


def test_get_expired_document(store, expired_document):
    with pytest.raises(DocumentStoreError) as e:
        store.get("service-id", "document-id", bytes(32))

    assert str(e.value) == "The document is no longer available"


def test_get_document_metadata_when_document_is_in_s3(store):
    metadata = store.get_document_metadata("service-id", "document-id", "0f0f0f")
    assert metadata == {
        "mimetype": "text/plain",
        "confirm_email": False,
        "size": 100,
        "available_until": "2020-04-30",
        "filename": None,
    }


def test_get_document_metadata_when_document_is_in_s3_with_hashed_email(store_with_email):
    metadata = store_with_email.get_document_metadata("service-id", "document-id", "0f0f0f")
    assert metadata == {
        "mimetype": "text/plain",
        "confirm_email": True,
        "size": 100,
        "available_until": "2020-04-30",
        "filename": None,
    }


def test_get_document_metadata_when_document_is_in_s3_with_filename(store_with_filename):
    metadata = store_with_filename.get_document_metadata("service-id", "document-id", "0f0f0f")
    assert metadata == {
        "mimetype": "text/plain",
        "confirm_email": False,
        "size": 100,
        "available_until": "2020-04-30",
        "filename": "✅.pdf",
    }


def test_get_document_metadata_when_document_is_not_in_s3(store):
    store.s3.head_object = mock.Mock(
        side_effect=BotoClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
    )

    assert store.get_document_metadata("service-id", "document-id", "0f0f0f") is None


def test_get_document_metadata_with_unexpected_boto_error(store):
    store.s3.head_object = mock.Mock(
        side_effect=BotoClientError({"Error": {"Code": "code", "Message": "Unhandled Exception"}}, "HeadObject")
    )

    with pytest.raises(DocumentStoreError):
        store.get_document_metadata("service-id", "document-id", "0f0f0f")


def test_get_document_metadata_with_blocked_document(store_with_email, blocked_document):
    assert store_with_email.get_document_metadata("service-id", "document-id", "0f0f0f") is None


def test_get_document_metadata_with_expired_document(store_with_email, expired_document):
    assert store_with_email.get_document_metadata("service-id", "document-id", "0f0f0f") is None


def test_authenticate_document_when_missing(store):
    store.s3.head_object = mock.Mock(
        side_effect=BotoClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
    )

    assert store.get_document_metadata("service-id", "document-id", "0f0f0f") is None

    assert store.authenticate("service-id", "document-id", b"0f0f0f", "test@notify.example") is False


@pytest.mark.parametrize(
    "email_address, expected_result",
    (
        ("bad@example.notify", False),
        ("test@notify.example", True),
    ),
)
def test_authenticate_document_email_address_check(store_with_email, email_address, expected_result):
    assert store_with_email.authenticate("service-id", "document-id", b"0f0f0f", email_address) is expected_result


def test_authenticate_fails_if_document_does_not_have_hash(store):
    with mock.patch.object(store, "_hasher") as mock_hasher:
        # Error on any attempt to use the hasher
        # Ensures we don't get through to hashing and return False from that, invalidating the test.
        mock.seal(mock_hasher)

        assert store.authenticate("service-id", "document-id", b"0f0f0f", "test@notify.example") is False


def test_authenticate_with_unexpected_boto_error(store):
    store.s3.head_object = mock.Mock(
        side_effect=BotoClientError({"Error": {"Code": "code", "Message": "Unhandled Exception"}}, "HeadObject")
    )

    with pytest.raises(DocumentStoreError):
        store.authenticate("service-id", "document-id", b"0f0f0f", "test@notify.example")


def test_authenticate_with_blocked_document(store, blocked_document):
    assert store.authenticate("service-id", "document-id", b"0f0f0f", "test@notify.example") is False


def test_authenticate_with_expired_document(store, expired_document):
    assert store.authenticate("service-id", "document-id", b"0f0f0f", "test@notify.example") is False


@pytest.mark.parametrize(
    "raw_expiry_rule,expected_date",
    [
        # An expiry date in winter time (GMT) - date in GMT ISO 8601 format
        ('expiry-date="Mon, 31 Oct 2022 00:00:00 GMT", rule-id="remove-old-documents"', date(2022, 10, 30)),
        # An expiry date in summer time (BST) - still sent by AWS in GMT ISO 8601 format.
        ('expiry-date="Wed, 26 Oct 2022 00:00:00 GMT", rule-id="remove-old-documents"', date(2022, 10, 25)),
        # Swap the order of the key-value pairs
        ('rule-id="remove-old-documents", expiry-date="Mon, 31 Oct 2022 00:00:00 GMT"', date(2022, 10, 30)),
        # Expiry date should handle month borders just fine
        ('rule-id="remove-old-documents", expiry-date="Tue, 01 Nov 2022 00:00:00 GMT"', date(2022, 10, 31)),
    ],
)
def test___convert_expiry_date_to_date_object(raw_expiry_rule, expected_date):
    result = DocumentStore._convert_expiry_date_to_date_object(raw_expiry_rule)
    assert result == expected_date


def test_convert_expiry_date_to_date_object_logs_on_non_gmt_expiration(app, caplog):
    DocumentStore._convert_expiry_date_to_date_object(
        'expiry-date="Mon, 31 Oct 2022 00:00:00 EST", rule-id="remove-old-documents"'
    )

    assert len(caplog.records) == 1
    assert caplog.records[0].message == "AWS S3 object expiration has unhandled timezone: EST"
