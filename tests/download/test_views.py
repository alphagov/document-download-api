import io
from unittest import mock
from uuid import UUID

import pytest
from flask import url_for

from app.utils.store import DocumentStoreError


@pytest.fixture
def store(mocker):
    return mocker.patch('app.download.views.document_store')


@pytest.mark.parametrize(('mimetype', 'expected_content_type'), [
    ('application/pdf', 'application/pdf'),
    ('text/plain', 'text/plain; charset=utf-8')
])
def test_document_download_open_in_browser_filetypes(
    mimetype,
    expected_content_type,
    client,
    store
):
    store.get.return_value = {
        'body': io.BytesIO(b'document contents'),
        'mimetype': mimetype,
        'size': 100
    }

    response = client.get(
        url_for(
            'download.download_document',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',  # 32 \x00 bytes
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b'document contents'
    assert dict(response.headers) == {
        'Cache-Control': mock.ANY,
        'Expires': mock.ANY,
        'Content-Length': '100',
        'Content-Type': expected_content_type,
        'X-B3-SpanId': 'None',
        'X-B3-TraceId': 'None',
        'X-Robots-Tag': 'noindex, nofollow'
    }
    store.get.assert_called_once_with(
        UUID('00000000-0000-0000-0000-000000000000'),
        UUID('ffffffff-ffff-ffff-ffff-ffffffffffff'),
        bytes(32)
    )


@pytest.mark.parametrize(('mimetype', 'expected_content_type', 'expected_extension'), [
    ('text/csv', 'text/csv; charset=utf-8', 'csv'),
    ('text/rtf', 'text/rtf; charset=utf-8', 'rtf'),
    ('application/rtf', 'application/rtf', 'rtf'),
    ('application/vnd.openxmlformats-officedocument.wordprocessingml.document',
     'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
     'docx')
])
def test_document_download_filename_direct_download_filetypes(
    mimetype,
    expected_content_type,
    expected_extension,
    client,
    store
):
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
        )
    )

    assert response.status_code == 200
    assert response.get_data() == b'a,b,c'
    assert dict(response.headers) == {
        'Cache-Control': mock.ANY,
        'Expires': mock.ANY,
        'Content-Length': '100',
        'Content-Type': expected_content_type,
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
            key='🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?'
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
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'something went wrong'}


def test_check_document_exists_without_decryption_key(client, store):
    response = client.get(
        url_for(
            'download.check_document_exists',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'Missing decryption key'}


def test_check_document_exists_with_invalid_decryption_key(client):
    response = client.get(
        url_for(
            'download.check_document_exists',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉🐦⁉?'
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'Invalid decryption key'}


def test_check_document_exists_document_store_error(client, store):
    store.check_document_exists.side_effect = DocumentStoreError('something went wrong')
    response = client.get(
        url_for(
            'download.check_document_exists',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    )

    assert response.status_code == 400
    assert response.json == {'error': 'something went wrong'}


def test_check_document_exists_when_document_is_in_s3(client, store):
    store.check_document_exists.return_value = True
    response = client.get(
        url_for(
            'download.check_document_exists',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    )

    assert response.status_code == 200
    assert response.json == {'file_exists': 'True'}
    assert response.headers['X-Robots-Tag'] == 'noindex, nofollow'


def test_check_document_exists_when_document_is_not_in_s3(client, store):
    store.check_document_exists.return_value = False
    response = client.get(
        url_for(
            'download.check_document_exists',
            service_id='00000000-0000-0000-0000-000000000000',
            document_id='ffffffff-ffff-ffff-ffff-ffffffffffff',
            key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    )

    assert response.status_code == 200
    assert response.json == {'file_exists': 'False'}
    assert response.headers['X-Robots-Tag'] == 'noindex, nofollow'
