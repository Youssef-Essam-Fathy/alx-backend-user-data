#!/usr/bin/env python3
""" Module of BasicAuth config
"""
from api.v1.auth.auth import Auth
from typing import Tuple
import re
import base64


class BasicAuth(Auth):
    """ class BasicAuth that inherits from Auth
    """
    def __init__(self) -> None:
        """ Initialize the Auth class
        """
        pass

    def extract_base64_authorization_header(
            self,
            authorization_header: str
    ) -> str:
        """ getting the Base64 of the string authorization_header

        Args:
            authorization_header (str): a string to split

        Returns:
            str: Base64 part of the Authorization header
            for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        else:
            splt = authorization_header.split()
            if len(splt) > 1:
                return splt[1]
            else:
                return None

    def decode_base64_authorization_header(
      self,
      base64_authorization_header: str
    ) -> str:
        """ Decoding the Base64 string base64_authorization_header

        Args:
            base64_authorization_header (str):
            a Base64 string to decode
        Returns:
            str: the decoded value of a
            Base64 string base64_authorization_header
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_str = base64.b64decode(base64_authorization_header)
            return decoded_str.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
    ) -> Tuple[str, str]:
        """_summary_

        Args:
            decoded_base64_authorization_header (str): _description_

        Returns:
            Tuple[str, str]: _description_
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if not decoded_base64_authorization_header.__contains__(':'):
            return (None, None)
        else:
            first_str, second_str = decoded_base64_authorization_header.split(
                ':'
            )
            return (first_str, second_str)
