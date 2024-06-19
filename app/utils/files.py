def split_filename(filename: str, *, dotted: bool) -> tuple[str, str]:
    *parts, ext = filename.split(".")
    name = ".".join(parts)
    return name, f".{ext}" if dotted else ext
