import re

from flask import current_app
from notifications_utils.recipient_validation.email_address import validate_and_format_email_address
from notifications_utils.recipient_validation.errors import InvalidEmailError

from app.utils.files import split_filename


def clean_and_validate_email_address(confirmation_email):
    if not isinstance(confirmation_email, str):
        raise InvalidEmailError("Confirmation email must be a string.")

    return validate_and_format_email_address(confirmation_email)


def clean_and_validate_retention_period(retention_period):
    error_message = "Retention period must be a string of the format '<1-78> weeks'."

    if not isinstance(retention_period, str):
        raise ValueError(error_message)

    retention_period = retention_period.lower().strip()

    matches = re.match(r"^(\d+) weeks?$", retention_period)
    if not matches:
        raise ValueError(error_message)

    weeks = int(matches.group(1))
    if not 0 < weeks <= 78:
        raise ValueError(error_message)

    if not retention_period.endswith("s"):
        retention_period += "s"

    return retention_period


def validate_filename(filename):
    if len(filename) > current_app.config["MAX_CUSTOM_FILENAME_LENGTH"]:
        raise ValueError(
            f"`filename` cannot be longer than {current_app.config['MAX_CUSTOM_FILENAME_LENGTH']} characters"
        )

    if "." not in filename:
        raise ValueError("`filename` must end with a file extension. For example, filename.csv")

    extension = split_filename(filename, dotted=False)[1]
    if extension not in current_app.config["FILE_EXTENSIONS_TO_MIMETYPES"]:
        allowed_file_types = ", ".join(sorted({f"'.{x}'" for x in current_app.config["FILE_EXTENSIONS_TO_MIMETYPES"]}))
        raise ValueError(f"Unsupported file type '.{extension}'. Supported types are: {allowed_file_types}")

    return filename
