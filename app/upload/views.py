import mimetypes
from base64 import b64decode, binascii
from io import BytesIO

from flask import Blueprint, abort, current_app, jsonify, request
from notifications_utils.recipients import InvalidEmailError
from werkzeug.exceptions import BadRequest

from app import antivirus_client, document_store
from app.utils import get_mime_type
from app.utils.antivirus import AntivirusError
from app.utils.authentication import check_auth
from app.utils.files import split_filename
from app.utils.urls import get_direct_file_url, get_frontend_download_url
from app.utils.validation import (
    clean_and_validate_email_address,
    clean_and_validate_retention_period,
    validate_filename,
)

upload_blueprint = Blueprint("upload", __name__, url_prefix="")
upload_blueprint.before_request(check_auth)


def _get_upload_document_request_data(data):  # noqa: C901
    if "document" not in data:
        raise BadRequest("No document upload")

    try:
        raw_content = b64decode(data["document"])
    except (binascii.Error, ValueError) as e:
        raise BadRequest("Document is not base64 encoded") from e

    if len(raw_content) > current_app.config["MAX_DECODED_FILE_SIZE"]:
        abort(413)
    file_data = BytesIO(raw_content)
    is_csv = data.get("is_csv", False)

    if not isinstance(is_csv, bool):
        raise BadRequest("Value for is_csv must be a boolean")

    confirmation_email = data.get("confirmation_email", None)
    if confirmation_email is not None:
        try:
            confirmation_email = clean_and_validate_email_address(confirmation_email)
        except InvalidEmailError as e:
            raise BadRequest(str(e)) from e

    retention_period = data.get("retention_period", None)
    if retention_period is not None:
        try:
            retention_period = clean_and_validate_retention_period(retention_period)
        except ValueError as e:
            raise BadRequest(str(e)) from e

    filename = data.get("filename", None)
    if filename:
        try:
            filename = validate_filename(filename)
        except ValueError as e:
            raise BadRequest(str(e)) from e

    return file_data, is_csv, confirmation_email, retention_period, filename


@upload_blueprint.route("/services/<uuid:service_id>/documents", methods=["POST"])
def upload_document(service_id):
    try:
        file_data, is_csv, confirmation_email, retention_period, filename = _get_upload_document_request_data(
            request.json
        )
    except BadRequest as e:
        return jsonify(error=e.description), 400

    if current_app.config["ANTIVIRUS_ENABLED"]:
        try:
            virus_free = antivirus_client.scan(file_data)
        except AntivirusError:
            return jsonify(error="Antivirus API error"), 503

        if not virus_free:
            return jsonify(error="File did not pass the virus scan"), 400

    if filename:
        mimetype = mimetypes.types_map[split_filename(filename, dotted=True)[1]]
    else:
        mimetype = get_mime_type(file_data)

        # Our mimetype auto-detection sometimes resolves CSV content as text/plain, so we use
        # an explicit POST body parameter `is_csv` from the caller to resolve it as text/csv
        if is_csv and mimetype == "text/plain":
            mimetype = "text/csv"

    if mimetype not in current_app.config["ALLOWED_FILE_TYPES"]:
        allowed_file_types = ", ".join(sorted({f"'.{x}'" for x in current_app.config["ALLOWED_FILE_TYPES"].values()}))
        return jsonify(error=f"Unsupported file type '{mimetype}'. Supported types are: {allowed_file_types}"), 400

    document = document_store.put(
        service_id,
        file_data,
        mimetype=mimetype,
        confirmation_email=confirmation_email,
        retention_period=retention_period,
        filename=filename,
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
