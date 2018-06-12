import binascii
from base64 import urlsafe_b64encode, urlsafe_b64decode
from urllib.parse import urlsplit, urlunsplit

from flask import current_app, url_for


def get_document_download_url(service_id, document_id, key):
    # key should be the raw bytes
    url = url_for(
        'download.download_document',
        service_id=service_id,
        document_id=document_id,
        key=bytes_to_key(key),
        _external=True
    )

    if current_app.config['PUBLIC_HOSTNAME']:
        url = urlunsplit(urlsplit(url)._replace(
            scheme="https",
            netloc=current_app.config['PUBLIC_HOSTNAME']
        ))

    return url


def key_to_bytes(key):
    try:
        # 32 bytes will always have one `=` of padding
        return urlsafe_b64decode(key + '=')
    except binascii.Error:
        raise ValueError('Could not decode decryption key')


def bytes_to_key(bytes):
    # remove trailing = for beautification purposes. This is fine because we know that we're always dealing with
    # 32 bytes, which will always give exactly one trailing slash.
    return urlsafe_b64encode(bytes).decode('ascii').rstrip('=')
