import uuid
from unittest import mock

import pytest
from botocore.exceptions import ClientError as BotoClientError

from app.utils.store import DocumentStore, DocumentStoreError
from tests.conftest import Matcher, set_config


@pytest.fixture
def store(mocker):
    mock_boto = mocker.patch('app.utils.store.boto3')
    mock_boto.client.return_value.get_object.return_value = {
        'Body': mock.Mock(),
        'ContentType': 'application/pdf',
        'ContentLength': 100
    }
    mock_boto.client.return_value.head_object.return_value = {
        'ResponseMetadata': {'RequestId': 'ABCD'},
        'Expiration': 'expiry-date="Fri, 01 May 2020 00:00:00 GMT"',
        'ContentType': 'text/plain'
    }
    store = DocumentStore(bucket='test-bucket')
    return store


@pytest.fixture
def store_with_email(mocker):
    mock_boto = mocker.patch('app.utils.store.boto3')
    mock_boto.client.return_value.get_object.return_value = {
        'Body': mock.Mock(),
        'ContentType': 'application/pdf',
        'ContentLength': 100
    }
    mock_boto.client.return_value.head_object.return_value = {
        'ResponseMetadata': {'RequestId': 'ABCD'},
        'Expiration': 'expiry-date="Fri, 01 May 2020 00:00:00 GMT"',
        'ContentType': 'text/plain',
        'Metadata': {
            'hashed-recipient-email': (
                # Hash of 'test@notify.example'
                '$argon2id$v=19$m=15360,t=2,p=1$ExyWUyRCJcqzJ+ip7SFZ2A$5SUu0QuYiF/kA9pdLsmE+A'
            )
        },
    }
    store = DocumentStore(bucket='test-bucket')
    return store


def test_document_store_init_app(app, store):
    with set_config(app, DOCUMENTS_BUCKET='test-bucket-2'):
        store.init_app(app)

    assert store.bucket == 'test-bucket-2'


def test_get_document_key(store):
    assert store.get_document_key('service-id', 'doc-id') == 'service-id/doc-id'


def test_document_key_with_uuid(store):
    service_id = uuid.uuid4()
    document_id = uuid.uuid4()

    assert store.get_document_key(service_id, document_id) == "{}/{}".format(str(service_id), str(document_id))


def test_put_document(store):
    ret = store.put('service-id', mock.Mock(), mimetype='application/pdf', verification_email=None)

    assert ret == {
        'id': Matcher('UUID length match', lambda x: len(x) == 36),
        'encryption_key': Matcher('32 bytes', lambda x: len(x) == 32 and isinstance(x, bytes))
    }

    store.s3.put_object.assert_called_once_with(
        Body=mock.ANY,
        Bucket='test-bucket',
        ContentType='application/pdf',
        Key=Matcher('document key', lambda x: x.startswith('service-id/') and len(x) == 11 + 36),
        SSECustomerKey=ret['encryption_key'],
        SSECustomerAlgorithm='AES256'
    )


def test_put_document_sends_hashed_recipient_email_to_s3_as_metadata_if_verification_email_present(store):
    ret = store.put(
        'service-id', mock.Mock(), mimetype='application/pdf', verification_email="email@example.com"
    )

    assert ret == {
        'id': Matcher('UUID length match', lambda x: len(x) == 36),
        'encryption_key': Matcher('32 bytes', lambda x: len(x) == 32 and isinstance(x, bytes))
    }

    store.s3.put_object.assert_called_once_with(
        Body=mock.ANY,
        Bucket='test-bucket',
        ContentType='application/pdf',
        Key=Matcher('document key', lambda x: x.startswith('service-id/') and len(x) == 11 + 36),
        SSECustomerKey=ret['encryption_key'],
        SSECustomerAlgorithm='AES256',
        Metadata={"hashed-recipient-email": mock.ANY}
    )


def test_get_document(store):
    assert store.get('service-id', 'document-id', bytes(32)) == {
        'body': mock.ANY,
        'mimetype': 'application/pdf',
        'size': 100,
    }

    store.s3.get_object.assert_called_once_with(
        Bucket='test-bucket',
        Key='service-id/document-id',
        SSECustomerAlgorithm='AES256',
        # 32 null bytes
        SSECustomerKey=bytes(32),
    )


def test_get_document_with_boto_error(store):
    store.s3.get_object = mock.Mock(side_effect=BotoClientError({
        'Error': {
            'Code': 'Error code',
            'Message': 'Error message'
        }
    }, 'GetObject'))

    with pytest.raises(DocumentStoreError):
        store.get('service-id', 'document-id', '0f0f0f')


def test_get_document_metadata_when_document_is_in_s3(store):
    metadata = store.get_document_metadata('service-id', 'document-id', '0f0f0f')
    assert metadata == {'mimetype': 'text/plain', 'verify_email': False}


def test_get_document_metadata_when_document_is_in_s3_with_hashed_email(store_with_email):
    metadata = store_with_email.get_document_metadata('service-id', 'document-id', '0f0f0f')
    assert metadata == {'mimetype': 'text/plain', 'verify_email': True}


def test_get_document_metadata_when_document_is_not_in_s3(store):
    store.s3.head_object = mock.Mock(side_effect=BotoClientError({
        'Error': {
            'Code': '404',
            'Message': 'Not Found'
        }
    }, 'HeadObject'))

    assert store.get_document_metadata('service-id', 'document-id', '0f0f0f') is None


def test_get_document_metadata_with_unexpected_boto_error(store):
    store.s3.head_object = mock.Mock(side_effect=BotoClientError({
        'Error': {
            'Code': 'code',
            'Message': 'Unhandled Exception'
        }
    }, 'HeadObject'))

    with pytest.raises(DocumentStoreError):
        store.get_document_metadata('service-id', 'document-id', '0f0f0f')


def test_authenticate_document_when_missing(store):
    store.s3.head_object = mock.Mock(side_effect=BotoClientError({
        'Error': {
            'Code': '404',
            'Message': 'Not Found'
        }
    }, 'HeadObject'))

    assert store.get_document_metadata('service-id', 'document-id', '0f0f0f') is None

    assert store.authenticate('service-id', 'document-id', b'0f0f0f', 'test@notify.example') is False


@pytest.mark.parametrize(
    'email_address, expected_result',
    (
        ('bad@example.notify', False),
        ('test@notify.example', True),
    )
)
def test_authenticate_document_email_address_check(store_with_email, email_address, expected_result):
    assert store_with_email.authenticate('service-id', 'document-id', b'0f0f0f', email_address) is expected_result


def test_authenticate_fails_if_document_does_not_have_hash(store):
    with mock.patch.object(store, '_hasher') as mock_hasher:
        # Error on any attempt to use the hasher
        # Ensures we don't get through to hashing and return False from that, invalidating the test.
        mock.seal(mock_hasher)

        assert store.authenticate('service-id', 'document-id', b'0f0f0f', 'test@notify.example') is False
