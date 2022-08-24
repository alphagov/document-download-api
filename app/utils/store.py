import os
import uuid

import boto3
from argon2 import PasswordHasher, Type
from botocore.exceptions import ClientError as BotoClientError


class DocumentStoreError(Exception):
    pass


class DocumentStore:
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

        if verification_email:
            hashed_recipient_email = self._hash_recipient_email(verification_email)
            self.s3.put_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                Body=document_stream,
                ContentType=mimetype,
                SSECustomerKey=encryption_key,
                SSECustomerAlgorithm='AES256',
                Metadata={"hashed-recipient-email": hashed_recipient_email}
            )
        else:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                Body=document_stream,
                ContentType=mimetype,
                SSECustomerKey=encryption_key,
                SSECustomerAlgorithm='AES256'
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
                'mimetype': metadata['ContentType']
            }
        except BotoClientError as e:
            if e.response['Error']['Code'] == '404':
                return None
            raise DocumentStoreError(e.response['Error'])

    def generate_encryption_key(self):
        return os.urandom(32)

    def get_document_key(self, service_id, document_id):
        return "{}/{}".format(service_id, document_id)

    def _hash_recipient_email(self, verification_email):
        """
        We pass in verification_email, which is recipient's email address.

        We then hash it with argon2ID as per algorithm and parameters laid out by OWASP:
        https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#password-hashing-algorithms

        And we returned hashed email address, to later store it in S3 as metadata.

        Before changing the params, consider how to migrate existing hashes (check the OWASP cheatsheet for more info)
        """
        hasher = PasswordHasher(
            memory_cost=15360,
            time_cost=2,
            parallelism=1,
            hash_len=16,
            type=Type.ID
        )

        return hasher.hash(verification_email)
