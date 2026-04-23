from flask import Blueprint, jsonify, request

from app import document_store
from app.utils.authentication import check_auth
from app.utils.file_checks import AntivirusAndMimeTypeCheckError, UploadedFile
from app.utils.urls import get_direct_file_url, get_frontend_download_url

upload_blueprint = Blueprint("upload", __name__, url_prefix="")
upload_blueprint.before_request(check_auth)


@upload_blueprint.route("/services/<uuid:service_id>/documents", methods=["POST"])
def upload_document(service_id):
    try:
        uploaded_file = UploadedFile.from_request_json(request.json, service_id=service_id)
    except AntivirusAndMimeTypeCheckError as e:
        return jsonify(error=e.message), e.status_code

    document = document_store.put(
        service_id,
        uploaded_file.file_data,
        mimetype=uploaded_file.mimetype,
        confirmation_email=uploaded_file.confirmation_email,
        retention_period=uploaded_file.retention_period,
        filename=uploaded_file.filename,
        recipients_csv_link=get_link_to_recipients_csv(uploaded_file.recipients_csv),
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
                    mimetype=uploaded_file.mimetype,
                ),
                "url": get_frontend_download_url(
                    service_id=service_id,
                    document_id=document["id"],
                    key=document["encryption_key"],
                ),
                "mimetype": uploaded_file.mimetype,
            },
        ),
        201,
    )


def get_link_to_recipients_csv(uploaded_file):
    recipient_csv_upload = document_store.put(
        uploaded_file.service_id,
        uploaded_file.recipients_csv,
        mimetype="text/csv",
        confirmation_email=None,
        retention_period=uploaded_file.retention_period,
    )

    return get_direct_file_url(
        service_id=uploaded_file.service_id,
        document_id=recipient_csv_upload["id"],
        key=recipient_csv_upload["encryption_key"],
        mimetype="text/csv",
    )
