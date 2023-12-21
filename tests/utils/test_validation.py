import pytest
from notifications_utils.recipients import InvalidEmailError

from app.utils.validation import (
    clean_and_validate_email_address,
    clean_and_validate_retention_period,
    validate_filename,
)


def test_clean_and_validate_email_address():
    with pytest.raises(InvalidEmailError) as e:
        clean_and_validate_email_address(False)

    assert str(e.value) == "Confirmation email must be a string."


def test_clean_and_validate_retention_period():
    assert clean_and_validate_retention_period("1 week") == "1 weeks"
    assert clean_and_validate_retention_period("1 weeks") == "1 weeks"
    assert clean_and_validate_retention_period("3 week") == "3 weeks"
    assert clean_and_validate_retention_period("78 week") == "78 weeks"


@pytest.mark.parametrize("value", [False, "3 days", "3weeks", "3 years", "potato", "0 weeks", "79 weeks", "ten weeks"])
def test_clean_and_validate_retention_period_invalid_values(value):
    with pytest.raises(ValueError) as e:
        clean_and_validate_retention_period(value)

    assert str(e.value) == "Retention period must be a string of the format '<1-78> weeks'."


@pytest.mark.parametrize("filename", ("file.csv", "my-file.csv", "my.dotted.file.csv", "!@£$%^&*().pdf"))
def test_validate_filename_happy_path(client, filename):
    assert validate_filename(filename) == filename


def test_validate_filename_needs_dot():
    with pytest.raises(ValueError) as e:
        validate_filename("my-filename")
    assert str(e.value) == "`filename` must end with a file extension. For example, filename.csv"


@pytest.mark.parametrize(
    "value, extension", (("something.odf", ".odf"), ("archive.zip", ".zip"), ("something.with.dots.gif", ".gif"))
)
def test_validate_filename_rejects_unknown_file_extensions(client, value, extension):
    with pytest.raises(ValueError) as e:
        validate_filename(value)
        assert str(e.value) == (
            f"Unsupported file type '{extension}'. "
            f"Supported types are: '.csv', '.doc', '.docx', '.json', '.odt', '.pdf', '.rtf', '.txt', '.xlsx'"
        )
