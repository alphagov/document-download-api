import os
import uuid

import boto3
from botocore.exceptions import ClientError as BotoClientError

from app.utils.hasher import Hasher


class DocumentStoreError(Exception):
    pass


class DocumentStore:
    _hasher = Hasher()

    def __init__(self, bucket=None):
        self.s3 = boto3.client("s3")
        self.bucket = bucket

    def init_app(self, app):
        self.bucket = app.config['DOCUMENTS_BUCKET']

    def put(self, service_id, document_stream, *, mimetype, verification_email=None):
        """
        returns dict {'id': 'some-uuid', 'encryption_key': b'32 byte encryption key'}
        """

        encryption_key = self.generate_encryption_key()
        document_id = str(uuid.uuid4())

        extra_kwargs = {}
        if verification_email:
            hashed_recipient_email = self._hasher.hash(verification_email)
            extra_kwargs['Metadata'] = {"hashed-recipient-email": hashed_recipient_email}

        self.s3.put_object(
            Bucket=self.bucket,
            Key=self.get_document_key(service_id, document_id),
            Body=document_stream,
            ContentType=mimetype,
            SSECustomerKey=encryption_key,
            SSECustomerAlgorithm='AES256',
            **extra_kwargs
        )

        return {
            'id': document_id,
            'encryption_key': encryption_key
        }

    def get(self, service_id, document_id, decryption_key):
        """
        decryption_key should be raw bytes
        """
        try:
            document = self.s3.get_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm='AES256'
            )

        except BotoClientError as e:
            raise DocumentStoreError(e.response['Error'])

        return {
            'body': document['Body'],
            'mimetype': document['ContentType'],
            'size': document['ContentLength']
        }

    def get_document_metadata(self, service_id, document_id, decryption_key):
        """
        decryption_key should be raw bytes
        """

        try:
            metadata = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm='AES256'
            )

            return {
                'mimetype': metadata['ContentType'],
                'verify_email': True if metadata.get('Metadata', {}).get('hashed-recipient-email', None) else False
            }
        except BotoClientError as e:
            if e.response['Error']['Code'] == '404':
                return None
            raise DocumentStoreError(e.response['Error'])

    def generate_encryption_key(self):
        return os.urandom(32)

    def get_document_key(self, service_id, document_id):
        return "{}/{}".format(service_id, document_id)

    def authenticate(self, service_id: str, document_id: str, decryption_key: bytes, email_address: str) -> bool:
        try:
            response = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm='AES256'
            )

        except BotoClientError as e:
            if e.response['Error']['Code'] == '404':
                return False

            return False

        hashed_email = response.get('Metadata', {}).get('hashed-recipient-email', None)

        if not hashed_email:
            return False

        return self._hasher.verify(value=email_address, hash_to_verify=hashed_email)
