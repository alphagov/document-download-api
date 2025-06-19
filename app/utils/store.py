import os
import re
import uuid
from datetime import UTC, date, datetime, timedelta
from urllib.parse import urlencode

import boto3
from botocore.exceptions import ClientError as BotoClientError
from dateutil import parser
from flask import current_app

from app.utils.hasher import Hasher


class DocumentStoreError(Exception):
    suggested_status_code = 400


class DocumentBlocked(DocumentStoreError):
    suggested_status_code = 403


class DocumentExpired(DocumentStoreError):
    suggested_status_code = 410


class DocumentNotFound(DocumentStoreError):
    suggested_status_code = 404


class CannotDetermineExpiration(Exception):
    pass


class DocumentStore:
    """
    This class is not thread-safe.
    """

    _hasher = Hasher()

    def __init__(self, bucket=None):
        self.s3 = boto3.client("s3")
        self.bucket = bucket

    def init_app(self, app):
        self.bucket = app.config["DOCUMENTS_BUCKET"]

    def _get_document_tags(self, service_id, document_id):
        try:
            return {
                item["Key"]: item["Value"]
                for item in self.s3.get_object_tagging(
                    Bucket=self.bucket, Key=self.get_document_key(service_id, document_id)
                )["TagSet"]
            }
        except BotoClientError as e:
            if e.response["Error"].get("ResourceType") == "DeleteMarker":
                # The S3 object has been marked as expired (eg by our retention period lifecycle policy)
                raise DocumentExpired("The document is no longer available") from e

            if e.response["Error"].get("Code") == "NoSuchKey":
                raise DocumentNotFound("The requested document could not be found") from e

            raise e

    def check_for_blocked_document(self, tags):
        """Raises an exception if access to the document has been blocked after creation

        This should be checked before any document access. This might be used to quickly prevent anyone from accessing
        a file that a service has sent out accidentally.

        Note that the `blocked` tag key MUST be in lowercase.
        """

        if tags.get("blocked", "false").lower() in {"true", "yes"}:
            raise DocumentBlocked("Access to the document has been blocked")

    @classmethod
    def check_for_expired_document(cls, s3_response, tags):
        effective_expiry_date = cls._get_effective_expiry_date(s3_response, tags)

        if not effective_expiry_date:
            current_app.logger.error(
                "Expiration information not available for document, attempting to serve it anyway.."
            )
            return

        if effective_expiry_date < date.today():
            raise DocumentExpired("The document is no longer available")

    def put(
        self, service_id, document_stream, *, mimetype, confirmation_email=None, retention_period=None, filename=None
    ):
        """
        confirmation_email and retention_period need to already be in a validated and known-good format
        by the time they come into this method.

        returns dict {'id': 'some-uuid', 'encryption_key': b'32 byte encryption key'}
        """

        encryption_key = self.generate_encryption_key()
        document_id = str(uuid.uuid4())

        extra_kwargs = {"Metadata": {}}
        if confirmation_email:
            hashed_recipient_email = self._hasher.hash(confirmation_email)
            extra_kwargs["Metadata"]["hashed-recipient-email"] = hashed_recipient_email
            current_app.logger.info(
                "Enabling email confirmation flow for %(service_id)s/%(document_id)s",
                {"service_id": service_id, "document_id": document_id},
            )

        tags = {
            # in case we lose S3's native timestamp for some reason
            "created-at": datetime.now(UTC).isoformat(timespec="seconds"),
        }

        if retention_period:
            tags["retention-period"] = retention_period
            current_app.logger.info(
                "Setting custom retention period for %(service_id)s/%(document_id)s: %(retention_period)s",
                {"service_id": service_id, "document_id": document_id, "retention_period": retention_period},
            )

        extra_kwargs["Tagging"] = urlencode(tags)

        if filename:
            # Convert utf-8 filenames to ASCII suitable for storing in AWS S3 Metadata.
            extra_kwargs["Metadata"]["filename"] = filename.encode("unicode_escape").decode("ascii")

        self.s3.put_object(
            Bucket=self.bucket,
            Key=self.get_document_key(service_id, document_id),
            Body=document_stream,
            ContentType=mimetype,
            SSECustomerKey=encryption_key,
            SSECustomerAlgorithm="AES256",
            **extra_kwargs,
        )

        return {"id": document_id, "encryption_key": encryption_key}

    def _normalise_metadata(self, raw_metadata):
        normalised_metadata = {}

        if "hashed-recipient-email" in raw_metadata:
            normalised_metadata["hashed-recipient-email"] = raw_metadata["hashed-recipient-email"]

        if "filename" in raw_metadata:
            # Undo the ASCII-ficiation that we use to store UTF-8 filenames in AWS S3 metadata.
            normalised_metadata["filename"] = raw_metadata["filename"].encode("ascii").decode("unicode_escape")

        return normalised_metadata

    def get(self, service_id, document_id, decryption_key):
        """
        decryption_key should be raw bytes
        """
        try:
            tags = self._get_document_tags(service_id, document_id)
            self.check_for_blocked_document(tags)
            s3_response = self.s3.get_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )
            self.check_for_expired_document(s3_response, tags)

        except BotoClientError as e:
            if e.response["Error"]["Code"] == "404":
                raise DocumentNotFound("The requested document could not be found") from e

            raise DocumentStoreError(e.response["Error"]) from e

        return {
            "body": s3_response["Body"],
            "mimetype": s3_response["ContentType"],
            "size": s3_response["ContentLength"],
            "metadata": self._normalise_metadata(s3_response["Metadata"]),
        }

    def get_document_metadata(self, service_id, document_id, decryption_key):
        """
        decryption_key should be raw bytes
        """

        try:
            tags = self._get_document_tags(service_id, document_id)
            self.check_for_blocked_document(tags)
            s3_response = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )
            self.check_for_expired_document(s3_response, tags)

            available_until = self._get_effective_expiry_date(s3_response, tags)
            return {
                "mimetype": s3_response["ContentType"],
                "confirm_email": self.get_email_hash(s3_response) is not None,
                "size": s3_response["ContentLength"],
                "available_until": str(available_until) if available_until else None,
                "filename": self._normalise_metadata(s3_response["Metadata"]).get("filename"),
            }
        except BotoClientError as e:
            if e.response["Error"]["Code"] == "404":
                raise DocumentNotFound("The requested document could not be found") from e

            raise DocumentStoreError(e.response["Error"]) from e

    @classmethod
    def _get_effective_expiry_date(cls, s3_response, tags):
        potential_expiry_dates = []

        try:
            potential_expiry_dates.append(cls._get_expiry_date_from_expiration_header(s3_response))
        except CannotDetermineExpiration as err:
            current_app.logger.warning("Cannot determine document expiration through Expiration header: %s", str(err))

        try:
            potential_expiry_dates.append(cls._get_expiry_date_from_tags(s3_response, tags))
        except CannotDetermineExpiration as err:
            current_app.logger.warning("Cannot determine document expiration through tags: %s", str(err))

        if potential_expiry_dates:
            return min(potential_expiry_dates)

        # in case we're having a maintenance issue/outage with our s3 bucket
        # we'd prefer to serve some files that should have been deleted (hopefully <14
        # days ago) instead of being unable to serve any documents to any users
        return None

    @staticmethod
    def _get_expiry_date_from_expiration_header(s3_response) -> date:
        pattern = re.compile(r'([^=\s]+?)="(.+?)"')
        expiry_date_as_dict = dict(pattern.findall(s3_response.get("Expiration") or "") or {})

        if "expiry-date" not in expiry_date_as_dict:
            raise CannotDetermineExpiration("No expiry-date found")

        expiry_date_string = expiry_date_as_dict["expiry-date"]

        timezone = expiry_date_string.split()[-1]
        if timezone != "GMT":
            raise CannotDetermineExpiration(f"AWS S3 object expiration has unhandled timezone: {timezone}")

        try:
            expiry_date = parser.parse(expiry_date_string)
        except parser.ParserError as err:
            raise CannotDetermineExpiration from err

        return expiry_date.date() - timedelta(days=1)

    @staticmethod
    def _get_expiry_date_from_tags(s3_response, tags):
        try:
            retention_period_match = re.fullmatch(r"(\d+) weeks", tags["retention-period"])
        except KeyError as err:
            raise CannotDetermineExpiration from err

        if retention_period_match is None:
            raise CannotDetermineExpiration("Cannot parse retention-period header")

        try:
            retention_period_days = int(retention_period_match.group(1), base=10) * 7
        except ValueError as err:
            raise CannotDetermineExpiration from err

        try:
            created_at = datetime.fromisoformat(tags["created-at"])
        except (KeyError, ValueError):
            created_at = s3_response["LastModified"]

        return created_at.date() + timedelta(days=retention_period_days)

    def generate_encryption_key(self):
        return os.urandom(32)

    def get_document_key(self, service_id, document_id):
        return f"{service_id}/{document_id}"

    def authenticate(self, service_id: str, document_id: str, decryption_key: bytes, email_address: str) -> bool:
        """
        email_address needs to be in a validated and known-good format before being passed to this method
        """
        try:
            tags = self._get_document_tags(service_id, document_id)
            self.check_for_blocked_document(tags)
            s3_response = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )
            self.check_for_expired_document(s3_response, tags)
        except (DocumentBlocked, DocumentExpired):
            return False
        except BotoClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise DocumentStoreError(e.response["Error"]) from e

        hashed_email = self.get_email_hash(s3_response)

        if not hashed_email:
            return False

        return self._hasher.verify(value=email_address, hash_to_verify=hashed_email)

    @staticmethod
    def get_email_hash(boto_response):
        return boto_response.get("Metadata", {}).get("hashed-recipient-email", None)
