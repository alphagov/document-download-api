import base64
import io
from pathlib import Path

import pytest

from app.utils.antivirus import AntivirusError


@pytest.fixture
def store(mocker):
    return mocker.patch('app.upload.views.document_store')


@pytest.fixture
def antivirus(mocker):
    return mocker.patch('app.upload.views.antivirus_client')


def _document_upload(client, url, file_content, content_type):
    if content_type == 'multipart/form-data':
        response = client.post(
            url,
            content_type=content_type,
            data={
                'document': (io.BytesIO(file_content), 'file.pdf')
            }
        )
    if content_type == 'application/json':
        response = client.post(
            url,
            json={
                'document': base64.b64encode(file_content).decode('utf-8'),
            }
        )
    return response


@pytest.mark.parametrize(
    'content_type',
    (
        'multipart/form-data',
        'application/json',
    )
)
def test_document_upload_returns_link_to_frontend(client, store, antivirus, content_type):
    store.put.return_value = {
        'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        'encryption_key': bytes(32),
    }

    antivirus.scan.return_value = True

    url = '/services/00000000-0000-0000-0000-000000000000/documents'
    file_content = b'%PDF-1.4 file contents'
    response = _document_upload(client, url, file_content, content_type)

    # Check that the contents of the file saved is as expected
    put_args, put_kwargs = store.put.call_args_list[0]
    saved_file = put_args[1]
    assert saved_file.read() == file_content

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
                '/documents/ffffffff-ffff-ffff-ffff-ffffffffffff.pdf',
                '?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ]),
            'mimetype': 'application/pdf',
        },
        'status': 'ok'
    }


@pytest.mark.parametrize(
    'content_type',
    (
        'multipart/form-data',
        'application/json',
    )
)
def test_document_upload_virus_found(client, store, antivirus, content_type):
    antivirus.scan.return_value = False

    url = '/services/12345678-1111-1111-1111-123456789012/documents'
    file_content = b'%PDF-1.4 file contents'
    response = _document_upload(client, url, file_content, content_type)

    assert response.status_code == 400
    assert response.json == {
        'error': "File did not pass the virus scan"
    }


@pytest.mark.parametrize(
    'content_type',
    (
        'multipart/form-data',
        'application/json',
    )
)
def test_document_upload_virus_scan_error(client, store, antivirus, content_type):
    antivirus.scan.side_effect = AntivirusError(503, 'connection error')

    url = '/services/12345678-1111-1111-1111-123456789012/documents'
    file_content = b'%PDF-1.4 file contents'
    response = _document_upload(client, url, file_content, content_type)

    assert response.status_code == 503
    assert response.json == {
        'error': "Antivirus API error"
    }


@pytest.mark.parametrize(
    'content_type',
    (
        'multipart/form-data',
        'application/json',
    )
)
def test_document_upload_unknown_type(client, content_type):
    url = '/services/12345678-1111-1111-1111-123456789012/documents'
    file_content = b'\x00pdf file contents\n'
    response = _document_upload(client, url, file_content, content_type)

    assert response.status_code == 400
    assert response.json['error'] == (
        "Unsupported file type 'application/octet-stream'. "
        "Supported types are: '.csv', '.doc', '.docx', '.odt', '.pdf', '.rtf', '.txt', '.xlsx'"
    )


@pytest.mark.parametrize(
    'content_type',
    (
        'multipart/form-data',
        'application/json',
    )
)
def test_document_file_size_just_right(client, store, antivirus, content_type):
    store.put.return_value = {
        'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        'encryption_key': bytes(32),
    }

    antivirus.scan.return_value = True

    url = '/services/12345678-1111-1111-1111-123456789012/documents'
    file_content = b'%PDF-1.5 ' + b'a' * (2 * 1024 * 1024 - 8)
    response = _document_upload(client, url, file_content, content_type)

    assert response.status_code == 201


@pytest.mark.parametrize(
    'content_type',
    (
        'multipart/form-data',
        'application/json',
    )
)
def test_document_file_size_too_large(client, content_type):
    url = '/services/12345678-1111-1111-1111-123456789012/documents'
    file_content = b'pdf' * 1024 * 1024
    response = _document_upload(client, url, file_content, content_type)

    assert response.status_code == 413
    assert response.json == {
        'error': "Uploaded file exceeds file size limit"
    }


def test_document_upload_no_document_multipart_form_data(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        content_type='multipart/form-data',
        data={
            'file': (io.BytesIO(b'%PDF-1.4 file contents'), 'file.pdf')
        }
    )

    assert response.status_code == 400


def test_document_upload_no_document_json(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        json={
            'file': base64.b64encode(b'%PDF-1.4 file contents').decode('utf-8'),
        },
    )

    assert response.status_code == 400


def test_unauthorized_document_upload_multipart_form_data(client):
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


def test_unauthorized_document_upload_json(client):
    response = client.post(
        '/services/12345678-1111-1111-1111-123456789012/documents',
        json={
            'document': base64.b64encode(b'%PDF-1.4 file contents').decode('utf-8'),
        },
        headers={
            'Authorization': None,
        }
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    'file_name,extra_form_data,expected_mimetype',
    (
        (
            'test.csv',
            {'is_csv': True},
            'text/csv',
        ),
        (
            'test.csv',
            {'is_csv': False},
            'text/plain',
        ),
        (
            'test.csv',
            {},
            'text/plain',
        ),
        (
            'test.txt',
            {'is_csv': True},
            'text/csv',
        ),
        (
            'test.txt',
            {'is_csv': False},
            'text/plain',
        ),
        (
            'test.txt',
            {},
            'text/plain',
        ),
        (
            'test.pdf',
            {'is_csv': True},
            'application/pdf',
        ),
        (
            'test.pdf',
            {'is_csv': False},
            'application/pdf',
        ),
        (
            'test.pdf',
            {},
            'application/pdf',
        ),
    )
)
def test_document_upload_csv_handling(
    app,
    client,
    store,
    antivirus,
    file_name,
    extra_form_data,
    expected_mimetype,
):

    store.put.return_value = {
        'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        'encryption_key': bytes(32),
    }

    antivirus.scan.return_value = True

    with open(Path(__file__).parent.parent / 'sample_files' / file_name, 'rb') as f:
        response = client.post(
            '/services/00000000-0000-0000-0000-000000000000/documents',
            json={
                'document': base64.b64encode(f.read()).decode('utf-8'),
                **extra_form_data,
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
            'mimetype': expected_mimetype,
            'direct_file_url': ''.join([
                'http://document-download.test',
                '/services/00000000-0000-0000-0000-000000000000',
                '/documents/ffffffff-ffff-ffff-ffff-ffffffffffff',
                f'.{app.config["ALLOWED_FILE_TYPES"][expected_mimetype]}',
                '?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ]),
        },
        'status': 'ok'
    }


def test_document_upload_bad_is_csv_value(client):
    with open(Path(__file__).parent.parent / 'sample_files' / 'test.csv', 'rb') as f:
        response = client.post(
            '/services/00000000-0000-0000-0000-000000000000/documents',
            json={
                'document': base64.b64encode(f.read()).decode('utf-8'),
                'is_csv': 'Foobar',
            }
        )

    assert response.status_code == 400
    assert response.json == {
        'error': 'Value for is_csv must be a boolean'
    }
