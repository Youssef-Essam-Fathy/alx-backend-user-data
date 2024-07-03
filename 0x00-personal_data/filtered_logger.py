#!/usr/bin/env python3
"""
Module for filtering sensitive information in log messages.
"""

import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Obfuscates specified fields in a log message.

    Args:
        fields (List[str]): A list of strings representing
        all fields to obfuscate.
        redaction (str): A string representing
        by what the field will be obfuscated.
        message (str): A string representing the log line.
        separator (str): A string representing
        by which character is separating all fields in the log line.

    Returns:
        str: The obfuscated log message.
    """
    for field in fields:
        pattern = rf"{field}=.*?{separator}"
        message = re.sub(pattern, f"{field}={redaction}{separator}", message)
    return message
