import mimetypes
from base64 import b64decode, binascii
from hashlib import sha1
from io import BytesIO

from flask import abort, current_app
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError
from notifications_utils.clients.redis import RequestCache
from notifications_utils.recipient_validation.errors import InvalidEmailError
from werkzeug.exceptions import BadRequest

from app import antivirus_client, redis_client
from app.utils import get_mime_type
from app.utils.files import split_filename
from app.utils.validation import (
    clean_and_validate_email_address,
    clean_and_validate_retention_period,
    validate_filename,
)

cache = RequestCache(redis_client)


class FiletypeError(Exception):
    def __init__(self, message=None, status_code=None):
        self.message = message
        self.status_code = status_code


class AntivirusAndMimeTypeCheckError(Exception):
    def __init__(self, message=None, status_code=None):
        self.message = message
        self.status_code = status_code


class UploadedFile:
    def __init__(self, file_data, is_csv, confirmation_email, retention_period, filename):
        self.file_data = file_data
        self.is_csv = is_csv
        self.filename = filename
        self.confirmation_email = confirmation_email
        self.retention_period = retention_period
        self.virus_free, self.mimetype = self.virus_free_and_mimetype

    @property
    def is_csv(self):
        return self._is_csv

    @is_csv.setter
    def is_csv(self, value):
        if value is None:
            value = False
        if not isinstance(value, bool):
            raise BadRequest("Value for is_csv must be a boolean")
        self._is_csv = value

    @property
    def confirmation_email(self):
        return getattr(self, "_confirmation_email", None)

    @confirmation_email.setter
    def confirmation_email(self, value):
        if value is None:
            return
        try:
            self._confirmation_email = clean_and_validate_email_address(value)
        except InvalidEmailError as e:
            raise BadRequest(str(e)) from e

    @property
    def retention_period(self):
        return getattr(self, "_retention_period", None)

    @retention_period.setter
    def retention_period(self, value):
        if value is None:
            return
        try:
            self._retention_period = clean_and_validate_retention_period(value)
        except ValueError as e:
            raise BadRequest(str(e)) from e

    @property
    def filename(self):
        return getattr(self, "_filename", None)

    @filename.setter
    def filename(self, value):
        if value is None:
            return
        try:
            self._filename = validate_filename(value)
        except ValueError as e:
            raise BadRequest(str(e)) from e

    @classmethod
    def from_request_json(cls, data):
        if "document" not in data:
            raise BadRequest("No document upload")

        try:
            raw_content = b64decode(data["document"])
        except (binascii.Error, ValueError) as e:
            raise BadRequest("Document is not base64 encoded") from e

        if len(raw_content) > current_app.config["MAX_DECODED_FILE_SIZE"]:
            abort(413)

        return cls(
            file_data=BytesIO(raw_content),
            is_csv=data.get("is_csv"),
            confirmation_email=data.get("confirmation_email"),
            retention_period=data.get("retention_period"),
            filename=data.get("filename", None),
        )

    @property
    def file_data_hash(self):
        file_data_hash = sha1(self.file_data.read()).hexdigest()
        self.file_data.seek(0)
        return file_data_hash

    @cache.set("file-checks-{file_data_hash}")
    def get_mime_type_and_run_antivirus_scan_json(self, file_data_hash):
        if file_data_hash != self.file_data_hash:
            raise RuntimeError("Wrong hash value passed to cache")
        try:
            return {"success": {"virus_free": self._virus_free, "mimetype": self._mimetype}}
        except Exception as e:
            return {"failure": {"error": e.message, "status_code": e.status_code}}

    @property
    def virus_free_and_mimetype(self):
        result = self.get_mime_type_and_run_antivirus_scan_json(self.file_data_hash)
        if "failure" in result:
            raise AntivirusAndMimeTypeCheckError(
                message=result["failure"]["error"],
                status_code=result["failure"]["status_code"],
            )
        return result["success"]["virus_free"], result["success"]["mimetype"]

    @property
    def _virus_free(self):
        if not current_app.config["ANTIVIRUS_ENABLED"]:
            return False
        try:
            virus_free = antivirus_client.scan(self.file_data)
        except AntivirusError as e:
            raise AntivirusError(message="Antivirus API error", status_code=503) from e
        if not virus_free:
            raise AntivirusError(message="File did not pass the virus scan", status_code=400)
        return virus_free

    @property
    def _mimetype(self):
        if self.filename:
            mimetype = mimetypes.types_map[split_filename(self.filename, dotted=True)[1]]
        else:
            mimetype = get_mime_type(self.file_data)
            # Our mimetype auto-detection sometimes resolves CSV content as text/plain, so we use
            # an explicit POST body parameter `is_csv` from the caller to resolve it as text/csv
            if self.is_csv and mimetype == "text/plain":
                mimetype = "text/csv"
        if mimetype not in current_app.config["MIME_TYPES_TO_FILE_EXTENSIONS"]:
            allowed_file_types = ", ".join(
                sorted({f"'.{x}'" for x in current_app.config["FILE_EXTENSIONS_TO_MIMETYPES"].keys()})
            )
            raise FiletypeError(
                message=f"Unsupported file type '{mimetype}'. Supported types are: {allowed_file_types}",
                status_code=400,
            )
        return mimetype
