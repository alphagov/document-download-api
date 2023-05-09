from urllib.parse import urlencode, urlunsplit

from flask import current_app, url_for
from notifications_utils.base64_uuid import bytes_to_base64, uuid_to_base64


def get_direct_file_url(service_id, document_id, key, mimetype):
    return url_for(
        "download.download_document",
        service_id=service_id,
        document_id=document_id,
        key=bytes_to_base64(key),
        extension=current_app.config["ALLOWED_FILE_TYPES"][mimetype],
        _external=True,
    )


def get_frontend_download_url(service_id, document_id, key, for_internal_use=False):
    """
    `for_internal_use` should be set to True when we are getting the document-download-frontend
    url in order to call it from this app. If it will be used externally or displayed it should
    be kept as False
    """
    scheme = current_app.config["HTTP_SCHEME"]
    netloc = current_app.config["FRONTEND_HOSTNAME"]

    if for_internal_use:
        netloc = current_app.config["FRONTEND_HOSTNAME_INTERNAL"]
    else:
        netloc = current_app.config["FRONTEND_HOSTNAME"]

    path = "d/{}/{}".format(uuid_to_base64(service_id), uuid_to_base64(document_id))
    query = urlencode({"key": bytes_to_base64(key)})

    return urlunsplit([scheme, netloc, path, query, None])
