from typing import Tuple


def split_filename(filename: str, *, dotted: bool) -> Tuple[str, str]:
    *parts, ext = filename.split(".")
    name = ".".join(parts)
    return name, f".{ext}" if dotted else ext
