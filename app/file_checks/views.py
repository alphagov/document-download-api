from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest

from app.utils.authentication import check_auth
from app.utils.file_checks import AntivirusAndMimeTypeCheckError, UploadedFile

file_checks_blueprint = Blueprint("file_checks", __name__, url_prefix="")
file_checks_blueprint.before_request(check_auth)


@file_checks_blueprint.route("/antivirus_and_mimetype_check", methods=["POST"])
def get_mime_type_and_run_antivirus_scan():
    try:
        uploaded_file = UploadedFile.from_request_json(request.json)
    except BadRequest as e:
        return jsonify(error=e.description), 400
    except AntivirusAndMimeTypeCheckError as e:
        return jsonify(error=e.message), e.status_code

    return jsonify(virus_free=uploaded_file.virus_free, mimetype=uploaded_file.mimetype), 200
