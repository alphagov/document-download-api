from urllib.parse import urlencode, urlunsplit

from flask import current_app, url_for
from notifications_utils.base64_uuid import bytes_to_base64, uuid_to_base64


def get_direct_file_url(service_id, document_id, key, mimetype):
    extension = None

    for ext, mimetypes in current_app.config['ALLOWED_FILE_TYPES'].items():
        if mimetype in mimetypes:
            extension = ext
            break

    return url_for(
        'download.download_document',
        service_id=service_id,
        document_id=document_id,
        key=bytes_to_base64(key),
        extension=extension,
        _external=True
    )


def get_frontend_download_url(service_id, document_id, key):
    scheme = current_app.config['HTTP_SCHEME']
    netloc = current_app.config['FRONTEND_HOSTNAME']
    path = 'd/{}/{}'.format(uuid_to_base64(service_id), uuid_to_base64(document_id))
    query = urlencode({'key': bytes_to_base64(key)})

    return urlunsplit([scheme, netloc, path, query, None])
