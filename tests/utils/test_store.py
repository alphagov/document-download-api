import uuid
from unittest import mock

import pytest
from botocore.exceptions import ClientError as BotoClientError

from tests.conftest import set_config, Matcher

from app.utils.store import DocumentStore, DocumentStoreError


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
    ret = store.put('service-id', mock.Mock(), mimetype='application/pdf')

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


def test_check_document_exists_when_document_is_in_s3(store):
    assert store.check_document_exists('service-id', 'document-id', '0f0f0f') is True


def test_check_document_exists_when_document_is_not_in_s3(store):
    store.s3.head_object = mock.Mock(side_effect=BotoClientError({
        'Error': {
            'Code': '404',
            'Message': 'Not Found'
        }
    }, 'HeadObject'))

    assert store.check_document_exists('service-id', 'document-id', '0f0f0f') is False


def test_check_document_exists_with_unexpected_boto_error(store):
    store.s3.head_object = mock.Mock(side_effect=BotoClientError({
        'Error': {
            'Code': 'code',
            'Message': 'Unhandled Exception'
        }
    }, 'HeadObject'))

    with pytest.raises(DocumentStoreError):
        store.check_document_exists('service-id', 'document-id', '0f0f0f')
