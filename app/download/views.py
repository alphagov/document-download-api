from uuid import UUID

from flask import Blueprint, current_app, jsonify, make_response, request, send_file

from app import document_store
from app.utils.urls import base64_to_bytes
from app.utils.store import DocumentStoreError

download_blueprint = Blueprint('download', __name__, url_prefix='')


@download_blueprint.route('/d/<base64_uuid:service_id>/<base64_uuid:document_id>', methods=['GET'])
def download_document(service_id, document_id):
    assert isinstance(service_id, UUID)
    if 'key' not in request.args:
        return jsonify(error='Missing decryption key'), 400

    try:
        key = base64_to_bytes(request.args['key'])
        if len(key) != 32:
            raise ValueError
    except ValueError:
        return jsonify(error='Invalid decryption key'), 400

    try:
        document = document_store.get(service_id, document_id, key)
    except DocumentStoreError as e:
        current_app.logger.info(
            'Failed to download document: {}'.format(e),
            extra={
                'service_id': service_id,
                'document_id': document_id,
            }
        )
        return jsonify(error=str(e)), 400

    response = make_response(send_file(document['body'], mimetype=document['mimetype']))
    response.headers['Content-Length'] = document['size']

    return response
