from uuid import UUID

import pytest
from werkzeug.routing import ValidationError

from app import Base64UUIDConverter


@pytest.mark.parametrize('url_val', [
    'AAAAAAAAAAAAAAAAAAAAAQ',
    'AAAAAAAAAAAAAAAAAAAAAQ=',  # even though this has invalid padding we put extra =s on the end so this is okay
    'AAAAAAAAAAAAAAAAAAAAAQ==',
])
def test_base64_converter_to_python(url_val):
    assert Base64UUIDConverter(None).to_python(url_val) == UUID(int=1)


@pytest.mark.parametrize('python_val', [
    UUID(int=1),
    '00000000-0000-0000-0000-000000000001'
])
def test_base64_converter_to_url(python_val):
    assert Base64UUIDConverter(None).to_url(python_val) == 'AAAAAAAAAAAAAAAAAAAAAQ'


@pytest.mark.parametrize('url_val', [
    'this_is_valid_base64_but_is_too_long_to_be_a_uuid',
    'this_one_has_emoji_➕➕➕',
])
def test_base64_converter_to_python_raises_validation_error(url_val):
    with pytest.raises(ValidationError):
        Base64UUIDConverter(None).to_python(url_val)


def test_base64_converter_to_url_raises_validation_error():
    with pytest.raises(ValidationError):
        Base64UUIDConverter(None).to_url(object())
