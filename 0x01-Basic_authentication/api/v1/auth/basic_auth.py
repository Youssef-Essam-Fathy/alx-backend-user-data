#!/usr/bin/env python3
""" Module of BasicAuth config
"""
from api.v1.auth.auth import Auth
from typing import Tuple, TypeVar
from models.user import User
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
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        
        email, password = decoded_base64_authorization_header.split(':', 1)
        return (email, password)

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
    ) -> TypeVar('User'):
        """_summary_

        Args:
            self (_type_): _description_
        """
        if user_email is None:
            return None
        elif type(user_email) is not str:
            return None
        elif user_pwd is None:
            return None
        elif type(user_pwd) is not str:
            return None

        from models.user import User

        try:
            user = User.search({'email': user_email})
        except Exception:
            return None

        if user is None:
            return None
        else:
            for u in user:
                if u.is_valid_password(user_pwd):
                    return u
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        retrieves and Overloads Auth and
        the User instance for a given request
        Args:
            request:

        Returns:

        """
        authorization_header = self.authorization_header(request)
        base64_authorization_header = self.extract_base64_authorization_header(
            authorization_header)
        decoded_base64_authorization_header = \
            self.decode_base64_authorization_header(
                base64_authorization_header)
        user_email, user_pwd = self.extract_user_credentials(
            decoded_base64_authorization_header)
        return self.user_object_from_credentials(user_email, user_pwd)
