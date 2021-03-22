from pathlib import Path

import pytest

from app.utils import get_mime_type


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
    with open(Path(__file__).parent.parent / 'sample_files' / filename, 'rb') as f:
        assert get_mime_type(f) == expected_mime_type
