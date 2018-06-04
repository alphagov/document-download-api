import io
import json

import pytest

from app.utils.antivirus import AntivirusError


@pytest.fixture
def store(mocker):
    return mocker.patch('app.upload.views.document_store')


@pytest.fixture
def antivirus(mocker):
    return mocker.patch('app.upload.views.antivirus_client')


def test_document_upload(client, store, antivirus):
    store.put.return_value = {
        'id': '12345678-2222-2222-2222-123456789012',
        'encryption_key': '42',
    }

    antivirus.scan.return_value = True

    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        }
    )

    assert response.status_code == 201
    assert json.loads(response.get_data(as_text=True)) == {
        'document': {
            'id': '12345678-2222-2222-2222-123456789012',
            'url': ''.join([
                'http://localhost',
                '/services/12345678-1111-1111-1111-123456789012',
                '/documents/12345678-2222-2222-2222-123456789012?key=42'
            ])
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
    assert json.loads(response.get_data(as_text=True)) == {
        'error': "Document didn't pass the virus scan"
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
    assert json.loads(response.get_data(as_text=True)) == {
        'error': "Antivirus API error"
    }


def test_document_upload_unknown_type(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'pdf file contents\n'), 'file.pdf')
        }
    )

    assert response.status_code == 400
    assert json.loads(response.get_data(as_text=True)) == {
        'error': "Unsupported document type 'text/plain'. Supported types are: ['application/pdf']"
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
