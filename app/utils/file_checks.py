import mimetypes

from flask import current_app
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError

from app import antivirus_client
from app.utils import get_mime_type
from app.utils.files import split_filename


class FiletypeError(Exception):
    def __init__(self, error_message=None, status_code=None):
        self.error_message = error_message
        self.status_code = status_code


def run_antivirus_checks(file_data):
    try:
        virus_free = antivirus_client.scan(file_data)
    except AntivirusError as e:
        raise AntivirusError(message="Antivirus API error", status_code=503) from e

    if not virus_free:
        raise AntivirusError(message="File did not pass the virus scan", status_code=400)
    return virus_free


def run_mimetype_checks(file_data, is_csv, filename=None):
    if filename:
        mimetype = mimetypes.types_map[split_filename(filename, dotted=True)[1]]
    else:
        mimetype = get_mime_type(file_data)
        # Our mimetype auto-detection sometimes resolves CSV content as text/plain, so we use
        # an explicit POST body parameter `is_csv` from the caller to resolve it as text/csv
        if is_csv and mimetype == "text/plain":
            mimetype = "text/csv"
    if mimetype not in current_app.config["MIME_TYPES_TO_FILE_EXTENSIONS"]:
        allowed_file_types = ", ".join(
            sorted({f"'.{x}'" for x in current_app.config["FILE_EXTENSIONS_TO_MIMETYPES"].keys()})
        )
        raise FiletypeError(
            error_message=f"Unsupported file type '{mimetype}'. Supported types are: {allowed_file_types}",
            status_code=400,
        )
    return mimetype
