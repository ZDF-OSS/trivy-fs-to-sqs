import subprocess
import json
import logging
from typing import Tuple, Optional, Dict, Any
import re


def make_filename_compatible(input_string):
    # Define a replacement dictionary for characters that are not allowed in filenames
    replacements = {
        '/': '_',
        ':': '-',
        '@': '_at_',
        '#': '_hash_',
        '%': '_percent_',
        '&': '_and_',
        '*': '_star_',
        '?': '_question_',
        ' ': '_',
        '.': '_',
        '-': '_'
    }

    # Replace each forbidden character with its replacement
    for forbidden_char, replacement in replacements.items():
        input_string = input_string.replace(forbidden_char, replacement)

    # Remove any other characters that are not alphanumeric or underscores
    input_string = re.sub(r'[^A-Za-z0-9_\-\.]', '', input_string)

    return input_string


def scan_directory(directory: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    result = subprocess.run(
        ["trivy", "rootfs", directory, "--format", "json", "--scanners", "vuln", "--severity", "HIGH,CRITICAL,MEDIUM"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        logging.error(f"Error scanning image {directory}: {result.stderr}")
        return None, result.stderr
    return json.loads(result.stdout), None
