import pytest

from app.utils.files import split_filename


@pytest.mark.parametrize(
    "filename, dotted, expected_name, expected_extension",
    (
        ("test.csv", False, "test", "csv"),
        ("test.csv", True, "test", ".csv"),
        ("test.pdf", False, "test", "pdf"),
        ("test.pdf", True, "test", ".pdf"),
        ("many.dots.in.filename.pdf", True, "many.dots.in.filename", ".pdf"),
        ("spaces in filename ew.xlsx", True, "spaces in filename ew", ".xlsx"),
        ("final&version.v2.xlsx.doc.bak", True, "final&version.v2.xlsx.doc", ".bak"),
    ),
)
def test_split_filename(filename, dotted, expected_name, expected_extension):
    assert split_filename(filename, dotted=dotted) == (expected_name, expected_extension)
