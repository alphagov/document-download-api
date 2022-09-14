import re

from notifications_utils.recipients import (
    InvalidEmailError,
    validate_and_format_email_address,
)


def clean_and_validate_email_address(verification_email):
    if not isinstance(verification_email, str):
        raise InvalidEmailError('Verification email must be a string.')

    return validate_and_format_email_address(verification_email)


def clean_and_validate_retention_period(retention_period):
    error_message = "Retention period must be a string of the format '<1-78> weeks'."

    if not isinstance(retention_period, str):
        raise ValueError(error_message)

    retention_period = retention_period.lower().strip()

    matches = re.match(r'^(\d+) weeks?$', retention_period)
    if not matches:
        raise ValueError(error_message)

    weeks = int(matches.group(1))
    if not 0 < weeks <= 78:
        raise ValueError(error_message)

    if not retention_period.endswith('s'):
        retention_period += 's'

    return retention_period
