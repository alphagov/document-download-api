from io import BytesIO
from zipfile import BadZipFile, ZipFile

import magic


def get_mime_type(document_stream):
    data = document_stream.read()
    document_stream.seek(0)

    mime_type = magic.from_buffer(data, mime=True)

    # some versions of libmagic mis-report docx, xlsx, etc. as a zip files (which they technically are),
    # so lets dive in and check the zip file headers to see if it looks like one of these.
    if mime_type == 'application/zip':
        try:
            filenames = ZipFile(BytesIO(data)).namelist()

            if 'word/document.xml' in filenames:
                mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            elif 'xl/workbook.xml' in filenames:
                mime_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        except BadZipFile:
            # dunno what this is, but it's not a zip and it's not an office format. octet-stream is a generic binary.
            mime_type = 'application/octet-stream'

    return mime_type
