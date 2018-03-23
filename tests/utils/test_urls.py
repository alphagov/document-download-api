from tests.conftest import set_config

from app.utils.urls import get_document_download_url


def test_download_url_returns_url_for(app, mocker):
    mocker.patch('app.utils.urls.url_for', return_value='http://localhost:7000/path?key=value')

    assert get_document_download_url(
        service_id='service-id', document_id='document-id', key='key'
    ) == 'http://localhost:7000/path?key=value'


def test_download_url_uses_public_hostname_when_set(app, mocker):
    mocker.patch('app.utils.urls.url_for', return_value='http://localhost:7000/path?key=value')

    with set_config(app, PUBLIC_HOSTNAME='download.example.com'):
        assert get_document_download_url(
            service_id='service-id', document_id='document-id', key='key'
        ) == 'https://download.example.com/path?key=value'
