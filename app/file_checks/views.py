from base64 import b64decode, binascii
from io import BytesIO

from flask import Blueprint, abort, current_app, jsonify, request
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError
from werkzeug.exceptions import BadRequest

from app.utils.authentication import check_auth
from app.utils.file_checks import FiletypeError, run_antivirus_checks, run_mimetype_checks

file_checks_blueprint = Blueprint("file_checks", __name__, url_prefix="")
file_checks_blueprint.before_request(check_auth)


def _get_upload_document_request_data(data):
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

    return file_data, is_csv


@file_checks_blueprint.route("/antivirus_and_mimetype_check", methods=["POST"])
def get_mime_type_and_run_antivirus_scan():
    try:
        (
            file_data,
            is_csv,
        ) = _get_upload_document_request_data(request.json)
    except BadRequest as e:
        return jsonify(error=e.description), 400
    try:
        virus_free = run_antivirus_checks(file_data)
    except AntivirusError as e:
        return jsonify(error=e.message), e.status_code
    try:
        mimetype = run_mimetype_checks(file_data, is_csv)
    except FiletypeError as e:
        return jsonify(error=e.error_message), e.status_code
    return jsonify(virus_free=virus_free, mimetype=mimetype), 200
