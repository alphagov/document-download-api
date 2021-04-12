import io
from unittest import mock
from uuid import UUID

import pytest
from flask import url_for

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
        url_for(
            'download.download_document',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',  # 32 \x00 bytes
            extension='pdf'
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b'PDF document contents'
    assert dict(response.headers) == {
        'Cache-Control': mock.ANY,
        'Expires': mock.ANY,
        'Content-Length': '100',
        'Content-Type': 'application/pdf',
        'X-B3-SpanId': 'None',
        'X-B3-TraceId': 'None',
        'X-Robots-Tag': 'noindex, nofollow'
    }
    store.get.assert_called_once_with(
        UUID('00000000-0000-0000-0000-000000000000'),
        UUID('ffffffff-ffff-ffff-ffff-ffffffffffff'),
        bytes(32)
    )


@pytest.mark.parametrize("mimetype, expected_extension, expected_content_type_header", [
    ('text/csv', 'csv', 'text/csv; charset=utf-8'),
    ('text/rtf', 'rtf', 'text/rtf; charset=utf-8'),
    ('application/rtf', 'rtf', 'application/rtf'),
])
def test_force_document_download(
    client,
    store,
    mimetype,
    expected_extension,
    expected_content_type_header
):
    """
    Test that file responses have the expected Content-Type/Content-Disposition
    required for browsers to download files in a way that is useful for users.
    """
    store.get.return_value = {
        'body': io.BytesIO(b'a,b,c'),
        'mimetype': mimetype,
        'size': 100
    }

    document_id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    response = client.get(
        url_for(
            'download.download_document',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id=document_id,
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',  # 32 \x00 bytes
            extension='foo'
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b'a,b,c'
    assert dict(response.headers) == {
        'Cache-Control': mock.ANY,
        'Expires': mock.ANY,
        'Content-Length': '100',
        'Content-Type': expected_content_type_header,
        'Content-Disposition': f'attachment; filename={document_id}.{expected_extension}',
        'X-B3-SpanId': 'None',
        'X-B3-TraceId': 'None',
        'X-Robots-Tag': 'noindex, nofollow'
    }
    store.get.assert_called_once_with(
        UUID('00000000-0000-0000-0000-000000000000'),
        UUID('ffffffff-ffff-ffff-ffff-ffffffffffff'),
        bytes(32)
    )


def test_document_download_without_decryption_key(client, store):
    response = client.get(
        url_for(
            'download.download_document',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            extension='foo',
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'Missing decryption key'}


def test_document_download_with_invalid_decryption_key(client):
    response = client.get(
        url_for(
            'download.download_document',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?',
            extension='foo',
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'Invalid decryption key'}


def test_document_download_document_store_error(client, store):
    store.get.side_effect = DocumentStoreError('something went wrong')
    response = client.get(
        url_for(
            'download.download_document',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            extension='foo',
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'something went wrong'}


def test_get_document_metadata_without_decryption_key(client, store):
    response = client.get(
        url_for(
            'download.get_document_metadata',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'Missing decryption key'}


def test_get_document_metadata_with_invalid_decryption_key(client):
    response = client.get(
        url_for(
            'download.get_document_metadata',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?'
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'Invalid decryption key'}


def test_get_document_metadata_document_store_error(client, store):
    store.get_document_metadata.side_effect = DocumentStoreError('something went wrong')
    response = client.get(
        url_for(
            'download.get_document_metadata',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'something went wrong'}


def test_get_document_metadata_when_document_is_in_s3(client, store):
    store.get_document_metadata.return_value = {'mimetype': 'text/plain'}
    response = client.get(
        url_for(
            'download.get_document_metadata',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    )

    assert response.status_code == 200
    assert response.headers['X-Robots-Tag'] == 'noindex, nofollow'
    assert response.json == {
        'file_exists': 'True',
        'document': {
            'direct_file_url': ''.join([
                'http://document-download.test',
                '/services/00000000-0000-0000-0000-000000000000',
                '/documents/ffffffff-ffff-ffff-ffff-ffffffffffff.txt',
                '?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ])
        }
    }


def test_get_document_metadata_when_document_is_not_in_s3(client, store):
    store.get_document_metadata.return_value = None
    response = client.get(
        url_for(
            'download.get_document_metadata',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    )

    assert response.status_code == 200
    assert response.json == {'file_exists': 'False', 'document': None}
    assert response.headers['X-Robots-Tag'] == 'noindex, nofollow'
