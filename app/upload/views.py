from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest

from app import document_store
from app.file_checks.views import UploadedFile
from app.utils.authentication import check_auth
from app.utils.urls import get_direct_file_url, get_frontend_download_url

upload_blueprint = Blueprint("upload", __name__, url_prefix="")
upload_blueprint.before_request(check_auth)


@upload_blueprint.route("/services/<uuid:service_id>/documents", methods=["POST"])
def upload_document(service_id):
    try:
        uploaded_file = UploadedFile.from_request_json(request.json)
    except BadRequest as e:
        return jsonify(error=e.description), 400

    result = uploaded_file.get_mime_type_and_run_antivirus_scan_json()
    if "success" in result.keys():
        virus_free = result.get("success").get("virus_free")
        mimetype = result.get("success").get("mimetype")
        if not virus_free:
            return jsonify(error="File did not pass the virus scan"), 400
    if "failure" in result.keys():
        error = result.get("failure").get("error")
        status_code = result.get("failure").get("status_code")
        return jsonify(error=error), status_code

    document = document_store.put(
        service_id,
        uploaded_file.file_data,
        mimetype=mimetype,
        confirmation_email=uploaded_file.confirmation_email,
        retention_period=uploaded_file.retention_period,
        filename=uploaded_file.filename,
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
