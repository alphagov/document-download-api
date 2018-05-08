import io

import requests
import requests_mock
import pytest

from app.utils.antivirus import AntivirusClient, AntivirusError


@pytest.fixture(scope='function')
def antivirus(client, mocker):
    client = AntivirusClient()
    current_app = mocker.Mock(config={
        'ANTIVIRUS_API_HOST': 'https://antivirus',
        'ANTIVIRUS_API_KEY': 'test-antivirus-key'
    })
    client.init_app(current_app)
    return client


def test_scan_document(antivirus):
    document = io.BytesIO(b'filecontents')
    with requests_mock.Mocker() as request_mock:
        request_mock.post('https://antivirus/scan', json={
            'ok': True
        }, request_headers={
            'Authorization': 'Bearer test-antivirus-key',
        }, status_code=200)

        resp = antivirus.scan(document)

    assert resp
    assert 'filecontents' in request_mock.last_request.text
    assert document.tell() == 0


def test_should_raise_for_status(antivirus):
    with pytest.raises(AntivirusError) as excinfo, requests_mock.Mocker() as request_mock:
        request_mock.post('https://antivirus/scan', json={
            'error': 'Antivirus error'
        }, status_code=400)

        antivirus.scan(io.BytesIO(b'document'))

    assert excinfo.value.message == 'Antivirus error'
    assert excinfo.value.status_code == 400


def test_should_raise_for_connection_errors(antivirus):
    with pytest.raises(AntivirusError) as excinfo, requests_mock.Mocker() as request_mock:
        request_mock.post(
            'https://antivirus/scan',
            exc=requests.exceptions.ConnectTimeout
        )

        antivirus.scan(io.BytesIO(b'document'))

    assert excinfo.value.message == 'connection error'
    assert excinfo.value.status_code == 503
