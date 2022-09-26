import pytest
from notifications_utils.recipients import InvalidEmailError

from app.utils.validation import (
    clean_and_validate_email_address,
    clean_and_validate_retention_period,
)


def test_clean_and_validate_email_address():
    with pytest.raises(InvalidEmailError) as e:
        clean_and_validate_email_address(False)

    assert str(e.value) == 'Confirmation email must be a string.'


def test_clean_and_validate_retention_period():
    assert clean_and_validate_retention_period('1 week') == '1 weeks'
    assert clean_and_validate_retention_period('1 weeks') == '1 weeks'
    assert clean_and_validate_retention_period('3 week') == '3 weeks'
    assert clean_and_validate_retention_period('78 week') == '78 weeks'


@pytest.mark.parametrize('value', [False, '3 days', '3weeks', '3 years', 'potato', '0 weeks', '79 weeks', 'ten weeks'])
def test_clean_and_validate_retention_period_invalid_values(value):
    with pytest.raises(ValueError) as e:
        clean_and_validate_retention_period(value)

    assert str(e.value) == "Retention period must be a string of the format '<1-78> weeks'."
