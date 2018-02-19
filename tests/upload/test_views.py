import io
import json

import pytest


@pytest.fixture
def store(mocker):
    return mocker.patch('app.upload.views.document_store')


def test_document_upload(client, store):
    store.put.return_value = {
        'id': '12345678-2222-2222-2222-123456789012',
        'encryption_key': '42',
    }

    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'pdf file contents'), 'file.pdf')
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


def test_document_upload_no_document(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'file': (io.BytesIO(b'pdf file contents'), 'file.pdf')
        }
    )

    assert response.status_code == 400


def test_unauthorized_document_upload(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'document': (io.BytesIO(b'pdf file contents'), 'file.pdf')
        },
        headers={
            'Authorization': None,
        }
    )

    assert response.status_code == 401
