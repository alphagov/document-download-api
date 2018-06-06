import magic


def get_mime_type(document_stream):
    try:
        mime_type = magic.from_buffer(document_stream.read(1024), mime=True)
    finally:
        document_stream.seek(0)

    return mime_type
