from pathlib import Path

import pytest

from app.utils import get_mime_type

sample_files_path = Path(__file__).parent.parent / 'sample_files'


@pytest.mark.parametrize(['filename', 'expected_mime_type'], [
    # supported by doc dl
    ('test.pdf', 'application/pdf'),
    ('test.csv', 'text/plain'),
    ('test.doc', 'application/msword'),
    ('test.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
    ('test.odt', 'application/vnd.oasis.opendocument.text'),
    ('test.rtf', 'text/rtf'),
    ('test.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
    # not supported by doc dl
    ('test.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'),
    ('test.zip', 'application/zip'),
    ('corrupted.zip', 'application/octet-stream'),
])
def test_get_mime_type(filename, expected_mime_type):
    file = open(sample_files_path / filename, 'rb')
    assert get_mime_type(file) == expected_mime_type


@pytest.mark.parametrize(['filename', 'expected_mime_type'], [
    ('test.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
])
def test_get_mime_type_zip_xml(
    filename,
    expected_mime_type,
    mocker
):
    # libmagic on PaaS sometimes mistakes docx, xlsx, etc. files as ZIPs
    mocker.patch('app.utils.magic.from_buffer', return_value='application/zip')

    file = open(sample_files_path / filename, 'rb')
    assert get_mime_type(file) == expected_mime_type
