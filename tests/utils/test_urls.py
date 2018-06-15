from uuid import UUID

from app.utils.urls import get_document_download_url


SAMPLE_KEY = bytes(range(32))
# the b64 has one trailing =, that we strip.
SAMPLE_B64 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'


def test_get_document_download_url_returns_frontend_url(app):
    assert get_document_download_url(
        service_id=UUID(int=0), document_id=UUID(int=1), key=SAMPLE_KEY
    ) == 'https://document-download-frontend-test/d/{}/{}?key={}'.format(
        'AAAAAAAAAAAAAAAAAAAAAA',
        'AAAAAAAAAAAAAAAAAAAAAQ',
        SAMPLE_B64
    )
