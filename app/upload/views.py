from base64 import b64decode, binascii
from io import BytesIO

from flask import abort, current_app, jsonify
from flask_openapi3 import APIBlueprint
from notifications_utils.recipients import InvalidEmailError
from werkzeug.exceptions import BadRequest

from app import antivirus_client, document_store
from app.openapi import UploadJson, UploadPath, upload_tag
from app.utils import get_mime_type
from app.utils.antivirus import AntivirusError
from app.utils.authentication import check_auth
from app.utils.urls import get_direct_file_url, get_frontend_download_url
from app.utils.validation import (
    clean_and_validate_email_address,
    clean_and_validate_retention_period,
)

upload_blueprint = APIBlueprint("upload", __name__, url_prefix="", abp_security=[{"bearer": []}])
upload_blueprint.before_request(check_auth)


def _get_upload_document_request_data(data: UploadJson):
    try:
        raw_content = b64decode(data.base64_document)
    except (binascii.Error, ValueError) as e:
        raise BadRequest("Document is not base64 encoded") from e

    if len(raw_content) > current_app.config["MAX_CONTENT_LENGTH"]:
        abort(413)
    file_data = BytesIO(raw_content)

    if (confirmation_email := data.confirmation_email) is not None:
        try:
            confirmation_email = clean_and_validate_email_address(data.confirmation_email)
        except InvalidEmailError as e:
            raise BadRequest(str(e)) from e

    if (retention_period := data.retention_period) is not None:
        try:
            retention_period = clean_and_validate_retention_period(data.retention_period)
        except ValueError as e:
            raise BadRequest(str(e)) from e

    return file_data, data.is_csv, confirmation_email, retention_period


@upload_blueprint.post("/services/<uuid:service_id>/documents", tags=[upload_tag])
def upload_document(path: UploadPath, body: UploadJson):
    service_id = path.service_id

    try:
        file_data, is_csv, confirmation_email, retention_period = _get_upload_document_request_data(body)
    except BadRequest as e:
        return jsonify(error=e.description), 400

    if current_app.config["ANTIVIRUS_ENABLED"]:
        try:
            virus_free = antivirus_client.scan(file_data)
        except AntivirusError:
            return jsonify(error="Antivirus API error"), 503

        if not virus_free:
            return jsonify(error="File did not pass the virus scan"), 400

    mimetype = get_mime_type(file_data)
    if mimetype not in current_app.config["ALLOWED_FILE_TYPES"]:
        allowed_file_types = ", ".join(sorted({f"'.{x}'" for x in current_app.config["ALLOWED_FILE_TYPES"].values()}))
        return jsonify(error=f"Unsupported file type '{mimetype}'. Supported types are: {allowed_file_types}"), 400

    # Our mimetype auto-detection resolves CSV content as text/plain, so we use
    # an explicit POST body parameter `is_csv` from the caller to resolve it as text/csv
    if is_csv and mimetype == "text/plain":
        mimetype = "text/csv"

    document = document_store.put(
        service_id,
        file_data,
        mimetype=mimetype,
        confirmation_email=confirmation_email,
        retention_period=retention_period,
    )

    return (
        jsonify(
            status="ok",
            document={
                "id": document["id"],
                "direct_file_url": get_direct_file_url(
                    service_id=service_id,
                    document_id=document["id"],
                    key=document["encryption_key"],
                    mimetype=mimetype,
                ),
                "url": get_frontend_download_url(
                    service_id=service_id,
                    document_id=document["id"],
                    key=document["encryption_key"],
                ),
                "mimetype": mimetype,
            },
        ),
        201,
    )
