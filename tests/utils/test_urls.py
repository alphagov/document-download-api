from uuid import UUID

from app.utils.urls import get_frontend_download_url, get_direct_file_url


SAMPLE_KEY = bytes(range(32))
# the b64 has one trailing =, that we strip.
SAMPLE_B64 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'


def test_get_frontend_download_url_returns_frontend_url(app):
    assert get_frontend_download_url(
        service_id=UUID(int=0), document_id=UUID(int=1), key=SAMPLE_KEY
    ) == 'https://document-download-frontend-test/d/{}/{}?key={}'.format(
        'AAAAAAAAAAAAAAAAAAAAAA',
        'AAAAAAAAAAAAAAAAAAAAAQ',
        SAMPLE_B64
    )


def test_get_direct_file_url_gets_local_url_without_compressing_uuids(app):
    assert get_direct_file_url(
        service_id=UUID(int=0), document_id=UUID(int=1), key=SAMPLE_KEY
    ) == 'http://document-download.test/services/{}/documents/{}?key={}'.format(
        '00000000-0000-0000-0000-000000000000',
        '00000000-0000-0000-0000-000000000001',
        SAMPLE_B64
    )
