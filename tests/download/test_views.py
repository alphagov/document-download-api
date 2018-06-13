import io
import json
from uuid import UUID
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
        '/d/{}/{}?key={}'.format(
            'AAAAAAAAAAAAAAAAAAAAAA',  # uuid all 0s
            '_____________________w',  # uuid all fs
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',  # 32 \x00 bytes
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b'PDF document contents'
    assert dict(response.headers) == {
        'Cache-Control': mock.ANY,
        'Expires': mock.ANY,
        'Content-Length': '100',
        'Content-Type': 'application/pdf',
        'NotifyRequestID': mock.ANY,
    }
    store.get.assert_called_once_with(
        UUID('00000000-0000-0000-0000-000000000000'),
        UUID('ffffffff-ffff-ffff-ffff-ffffffffffff'),
        bytes(32)
    )


def test_document_download_without_decryption_key(client, store):
    response = client.get(
        '/d/AAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAA',
    )

    assert response.status_code == 400


@pytest.mark.parametrize('invalid_key', [
    'not_long_enough',
    '🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?'
    '🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?'
])
def test_document_download_with_invalid_decryption_key(client, invalid_key):
    response = client.get(
        '/d/AAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAA?key={}'.format(invalid_key),
    )

    assert response.status_code == 400
    assert json.loads(response.get_data(as_text=True)) == {'error': 'Invalid decryption key'}


def test_document_download_document_store_error(client, store):
    store.get.side_effect = DocumentStoreError('something went wrong')
    response = client.get(
        '/d/{}/{}?key={}'.format(
            'AAAAAAAAAAAAAAAAAAAAAA',
            '_____________________w',
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        )
    )

    assert response.status_code == 400
    assert json.loads(response.get_data(as_text=True)) == {'error': 'something went wrong'}


@pytest.mark.parametrize('url', [
    # a uuid instead of b64 string
    '/d/00000000-0000-0000-0000-000000000000/AAAAAAAAAAAAAAAAAAAAAA',
    '/d/AAAAAAAAAAAAAAAAAAAAAA/00000000-0000-0000-0000-000000000000',
    # too long to be a UUID
    '/d/AAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAA',
    # characters that aren't in base64 encoding
    '/d/🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉/AAAAAAAAAAAAAAAAAAAAAA',
])
def test_get_document_404s_with_invalid_IDs(client, url):
    response = client.get(
        url,
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        }
    )
    assert response.status_code == 404
