from flask import Blueprint, jsonify, request, url_for

from app import document_store
from app.utils.authentication import check_auth
from app.utils.urls import get_document_download_url

upload_blueprint = Blueprint('upload', __name__, url_prefix='')
upload_blueprint.before_request(check_auth)


@upload_blueprint.route('/services/<uuid:service_id>/documents', methods=['POST'])
def upload_document(service_id):
    if 'document' not in request.files:
        return jsonify(error='No document upload'), 400

    document = document_store.put(service_id, request.files['document'])

    return jsonify(
        status='ok',
        document={
            'id': document['id'],
            'url': get_document_download_url(
                service_id=service_id,
                document_id=document['id'],
                key=document['encryption_key'],
            )
        }
    ), 201
