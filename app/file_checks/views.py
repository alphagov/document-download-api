from flask import Blueprint, jsonify, request

from app.utils.authentication import check_auth
from app.utils.file_checks import AntivirusAndMimeTypeCheckError, UploadedFile

file_checks_blueprint = Blueprint("file_checks", __name__, url_prefix="")
file_checks_blueprint.before_request(check_auth)


@file_checks_blueprint.route("/services/<uuid:service_id>/antivirus-and-mimetype-check", methods=["POST"])
def get_mime_type_and_run_antivirus_scan(service_id):
    try:
        uploaded_file = UploadedFile.from_request_json(request.json, service_id=service_id)
    except AntivirusAndMimeTypeCheckError as e:
        return jsonify(error=e.message), e.status_code

    return jsonify(mimetype=uploaded_file.mimetype), 200
