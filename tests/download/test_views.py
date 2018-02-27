import io
import json
from unittest import mock

import pytest

from app.utils.store import DocumentStoreError


@pytest.fixture
def store(mocker):
    return mocker.patch('app.download.views.document_store')


def test_document_download(client, store):
    store.get.return_value = {
        'body': io.BytesIO(b'PDF document contents'),
        'mimetype': 'application/pdf',
        'size': 100
    }

    response = client.get(
        '/services/12345678-1111-1111-1111-123456789012/documents/12345678-2222-2222-2222-123456789012?key=4242',
    )

    assert response.status_code == 200
    assert response.get_data() == b'PDF document contents'
    assert dict(response.headers) == {
        'Cache-Control': mock.ANY,
        'Expires': mock.ANY,
        'Content-Length': '100',
        'Content-Type': 'application/pdf'
    }


def test_document_download_without_decryption_key(client, store):
    response = client.get(
        '/services/12345678-1111-1111-1111-123456789012/documents/12345678-2222-2222-2222-123456789012',
    )

    assert response.status_code == 400


def test_document_download_document_store_error(client, store):
    store.get.side_effect = DocumentStoreError('Invalid key')

    response = client.get(
        '/services/12345678-1111-1111-1111-123456789012/documents/12345678-2222-2222-2222-123456789012?key=4242',
    )

    assert response.status_code == 400
    assert json.loads(response.get_data(as_text=True)) == {'error': 'Invalid key'}
