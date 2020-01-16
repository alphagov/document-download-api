import io

import pytest

from app.utils.antivirus import AntivirusError


@pytest.fixture
def store(mocker):
    return mocker.patch('app.upload.views.document_store')


@pytest.fixture
def antivirus(mocker):
    return mocker.patch('app.upload.views.antivirus_client')


def test_document_upload_returns_link_to_frontend(client, store, antivirus):
    store.put.return_value = {
        'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        'encryption_key': bytes(32),
    }

    antivirus.scan.return_value = True

    response = client.post(
        '/services/00000000-0000-0000-0000-000000000000/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        }
    )

    assert response.status_code == 201
    assert response.json == {
        'document': {
            'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
            'url': ''.join([
                'https://document-download-frontend-test',
                '/d/AAAAAAAAAAAAAAAAAAAAAA',
                '/_____________________w',
                '?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ]),
            'direct_file_url': ''.join([
                'http://document-download.test',
                '/services/00000000-0000-0000-0000-000000000000',
                '/documents/ffffffff-ffff-ffff-ffff-ffffffffffff',
                '?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ]),
        },
        'status': 'ok'
    }


def test_document_upload_virus_found(client, store, antivirus):
    antivirus.scan.return_value = False

    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        }
    )

    assert response.status_code == 400
    assert response.json == {
        'error': "File didn't pass the virus scan"
    }


def test_document_upload_virus_scan_error(client, store, antivirus):
    antivirus.scan.side_effect = AntivirusError(503, 'connection error')

    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        }
    )

    assert response.status_code == 503
    assert response.json == {
        'error': "Antivirus API error"
    }


def test_document_upload_unknown_type(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'\x00pdf file contents\n'), 'file.pdf')
        }
    )

    assert response.status_code == 400
    assert response.json['error'] == (
        "Unsupported file type 'application/octet-stream'. Supported types are: '.csv', '.doc', '.docx', '.pdf', '.txt'"
    )


def test_document_file_size_just_right(client, store, antivirus):
    store.put.return_value = {
        'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        'encryption_key': bytes(32),
    }

    antivirus.scan.return_value = True

    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'%PDF-1.5 ' + b'a' * (2 * 1024 * 1024 - 8)), 'file.pdf')
        }
    )

    assert response.status_code == 201


def test_document_file_size_too_large(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'pdf' * 1024 * 1024), 'file.pdf')
        }
    )

    assert response.status_code == 413
    assert response.json == {
        'error': "Uploaded file exceeds file size limit"
    }


def test_document_upload_no_document(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'file': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        }
    )

    assert response.status_code == 400


def test_unauthorized_document_upload(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        },
        headers={
            'Authorization': None,
        }
    )

    assert response.status_code == 401
