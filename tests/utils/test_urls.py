from tests.conftest import set_config

from app.utils.urls import get_document_download_url


SAMPLE_KEY = bytes(range(32))
# the b64 has one trailing slash, that we strip.
SAMPLE_B64 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'


def test_download_url_returns_url_for(app):
    assert get_document_download_url(
        service_id='service-id', document_id='document-id', key=SAMPLE_KEY
    ) == 'http://document-download-test/services/service-id/documents/document-id?key={}'.format(SAMPLE_B64)


def test_download_url_uses_public_hostname_when_set(app):
    with set_config(app, PUBLIC_HOSTNAME='download.example.com'):
        assert get_document_download_url(
            service_id='service-id', document_id='document-id', key=SAMPLE_KEY
        ).startswith('https://download.example.com/')
