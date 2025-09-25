import mimetypes
from base64 import b64decode, binascii
from io import BytesIO

from flask import Blueprint, abort, current_app, jsonify, request
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError
from werkzeug.exceptions import BadRequest

from app import antivirus_client
from app.utils import get_mime_type
from app.utils.authentication import check_auth
from app.utils.files import split_filename

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
def get_mime_type_and_run_antivirus_scan(filename=None):
    try:
        (
            file_data,
            is_csv,
        ) = _get_upload_document_request_data(request.json)
    except BadRequest as e:
        return jsonify(error=e.description), 400
    virus_free = False
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
    if mimetype not in current_app.config["MIME_TYPES_TO_FILE_EXTENSIONS"]:
        allowed_file_types = ", ".join(
            sorted({f"'.{x}'" for x in current_app.config["FILE_EXTENSIONS_TO_MIMETYPES"].keys()})
        )
        return jsonify(error=f"Unsupported file type '{mimetype}'. Supported types are: {allowed_file_types}"), 400
    return jsonify(virus_free=virus_free, mimetype=mimetype), 200
