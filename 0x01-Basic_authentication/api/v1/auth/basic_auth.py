#!/usr/bin/env python3
""" Module of BasicAuth config
"""
from api.v1.auth.auth import Auth


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
