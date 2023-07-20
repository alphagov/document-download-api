from flask import (
    current_app,
    jsonify,
    make_response,
    redirect,
    request,
    send_file,
)
from flask_openapi3 import APIBlueprint
from notifications_utils.base64_uuid import base64_to_bytes
from notifications_utils.recipients import InvalidEmailError

from app import document_store, redis_client
from app.openapi import DownloadBody, DownloadPath, DownloadQuery, download_tag, healthcheck_tag
from app.utils.signed_data import (
    sign_service_and_document_id,
    verify_signed_service_and_document_id,
)
from app.utils.store import DocumentStoreError
from app.utils.urls import get_direct_file_url, get_frontend_download_url
from app.utils.validation import clean_and_validate_email_address

download_blueprint = APIBlueprint("download", __name__, url_prefix="")

FILE_TYPES_TO_FORCE_DOWNLOAD_FOR = ["csv", "rtf"]


@download_blueprint.get("/services/_status", tags=[healthcheck_tag])
def status():
    return "ok", 200


def get_redirect_url_if_user_not_authenticated(request, document):
    # if document doesn't have hashed email, always allow unauthed access
    if "hashed-recipient-email" not in document["metadata"]:
        return

    service_id = request.view_args["service_id"]
    document_id = request.view_args["document_id"]

    if signed_data := request.cookies.get("document_access_signed_data"):

        if verify_signed_service_and_document_id(signed_data, service_id, document_id):
            return

    url = get_frontend_download_url(service_id, document_id, base64_to_bytes(request.args["key"]))

    current_app.logger.warning("could not verify cookie for service %s document %s", service_id, document_id)
    return redirect(url)


# Some browsers - Firefox, IE11 - use the final part of the URL as the filename when downloading a file. While we
# don't use the extension, having it in the URL ensures the downloaded file can be opened correctly on Windows.
#
# The duplicate route - without the extension - is still used by some users, probably because they've bookmarked
# the direct URL to the file. We should be able to delete this once all the old documents have expired (18 months).
@download_blueprint.get(
    "/services/<uuid:service_id>/documents/<uuid:document_id>.<extension>", tags=[download_tag], doc_ui=False
)
@download_blueprint.get(
    "/services/<uuid:service_id>/documents/<uuid:document_id>", tags=[download_tag], security=[{"cookie": []}]
)
def download_document(path: DownloadPath, query: DownloadQuery):
    service_id, document_id = path.service_id, path.document_id

    if query.base64_key is None:
        return jsonify(error="Missing decryption key"), 400

    try:
        key = base64_to_bytes(query.base64_key)
    except ValueError:
        return jsonify(error="Invalid decryption key"), 400

    try:
        document = document_store.get(service_id, document_id, key)
    except DocumentStoreError as e:
        current_app.logger.info(
            "Failed to download document: %s",
            e,
            extra={
                "service_id": service_id,
                "document_id": document_id,
            },
        )
        return jsonify(error=str(e)), 400

    if redirect := get_redirect_url_if_user_not_authenticated(request, document):
        return redirect

    mimetype = document["mimetype"]
    send_file_kwargs = {"mimetype": mimetype}
    extension = current_app.config["ALLOWED_FILE_TYPES"][mimetype]

    if extension in FILE_TYPES_TO_FORCE_DOWNLOAD_FOR:
        # Give CSV files the 'Content-Disposition' header to ensure they are downloaded
        # rather than shown as raw text in the users browser
        send_file_kwargs.update(
            {
                "download_name": f"{document_id}.{extension}",
                "as_attachment": True,
            }
        )

    response = make_response(
        send_file(
            document["body"],
            **send_file_kwargs,
        )
    )
    response.headers["Content-Length"] = document["size"]
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


@download_blueprint.get("/services/<uuid:service_id>/documents/<uuid:document_id>/check", tags=[download_tag])
def get_document_metadata(path: DownloadPath, query: DownloadQuery):
    service_id, document_id = path.service_id, path.document_id

    if not query.base64_key:
        return jsonify(error="Missing decryption key"), 400

    try:
        key = base64_to_bytes(query.base64_key)
    except ValueError:
        return jsonify(error="Invalid decryption key"), 400

    try:
        metadata = document_store.get_document_metadata(service_id, document_id, key)
    except DocumentStoreError as e:
        current_app.logger.warning(
            "Failed to get document metadata: %s",
            e,
            extra={
                "service_id": service_id,
                "document_id": document_id,
            },
        )
        return jsonify(error=str(e)), 400

    if metadata:
        document = {
            "direct_file_url": get_direct_file_url(
                service_id=service_id,
                document_id=document_id,
                key=key,
                mimetype=metadata["mimetype"],
            ),
            "confirm_email": metadata["confirm_email"],
            "size_in_bytes": metadata["size"],
            "file_extension": current_app.config["ALLOWED_FILE_TYPES"][metadata["mimetype"]],
            "available_until": metadata["available_until"],
        }
    else:
        document = None

    response = make_response({"document": document})
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Referrer-Policy"] = "no-referrer"

    # Max cache duration of 30 minutes as we want to be able to re-check `blocked` tags.
    # The `blocked` tag will still get checked when trying to download the file so this cache length isn't necessary,
    # but will help us serve nicer pages on document-download-frontend when we know the file won't be downloadable.
    response.cache_control.max_age = 1800

    return response


@download_blueprint.post("/services/<uuid:service_id>/documents/<uuid:document_id>/authenticate", tags=[download_tag])
def authenticate_access_to_document(path: DownloadPath, body: DownloadBody):
    service_id, document_id = path.service_id, path.document_id

    rate_limit, rate_interval = (
        current_app.config["DOCUMENT_AUTHENTICATION_RATE_LIMIT"],
        current_app.config["DOCUMENT_AUTHENTICATE_RATE_INTERVAL_SECONDS"],
    )
    if redis_client.exceeded_rate_limit(
        f"authenticate-document-{service_id}-{document_id}",
        limit=rate_limit,
        interval=rate_interval,
    ):
        return (
            jsonify(error=f"Too many requests - more than {rate_limit} in the last {rate_interval} seconds"),
            429,
            {"Retry-After": rate_interval},
        )

    try:
        key = base64_to_bytes(body.base64_key)
    except ValueError:
        return jsonify(error="Invalid decryption key"), 400

    try:
        email_address = clean_and_validate_email_address(body.email_address)
    except InvalidEmailError:
        return jsonify(error="Invalid email address"), 400

    if document_store.authenticate(service_id, document_id, key, email_address) is False:
        return jsonify(error="Authentication failure"), 403

    return jsonify(
        signed_data=sign_service_and_document_id(service_id, document_id),
        direct_file_url=get_direct_file_url(
            service_id=service_id,
            document_id=document_id,
            key=key,
            mimetype=document_store.get_document_metadata(service_id, document_id, key)["mimetype"],
        ),
    )
