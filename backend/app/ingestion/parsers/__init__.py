from .base import LogParser
from .generic import GenericParser
from .apache import ApacheParser
from .nginx import NginxParser
from .linux_auth import LinuxAuthParser
from .windows import WindowsJsonParser

# Order matters: try more specific parsers first
AVAILABLE_PARSERS = [
    WindowsJsonParser(),
    ApacheParser(),
    NginxParser(),
    LinuxAuthParser(),
    GenericParser()
]

def get_parser(raw_line: str) -> LogParser:
    for parser in AVAILABLE_PARSERS:
        if parser.can_parse(raw_line):
            return parser
    return AVAILABLE_PARSERS[-1]  # GenericParser
