from urllib.parse import urlsplit, urlunsplit
from flask import current_app, url_for


def get_document_download_url(service_id, document_id, key):
    url = url_for(
        'download.download_document',
        service_id=service_id,
        document_id=document_id,
        key=key,
        _external=True
    )

    if current_app.config['PUBLIC_HOSTNAME']:
        url = urlunsplit(urlsplit(url)._replace(
            scheme="https",
            netloc=current_app.config['PUBLIC_HOSTNAME']
        ))

    return url
