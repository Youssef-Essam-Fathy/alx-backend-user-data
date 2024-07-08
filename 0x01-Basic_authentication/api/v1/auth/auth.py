#!/usr/bin/env python3
""" Module of Auth config
"""
from flask import request
from typing import (
    List,
    TypeVar as TypeVar
)


class Auth():
    """ Auth class for managing API authentication
    """
    def __init__(self) -> None:
        """ Initialize the Auth class
        """
        pass

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines if authentication is required
        based on the path and excluded paths.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): List of paths
            that do not require authentication.

        Returns:
            bool: True if authentication is required,
            False otherwise.
        """
        if path is None:
            return True
        if path in excluded_paths:
            return False
        if excluded_paths is None or excluded_paths == []:
            return True
        if not path.endswith('/'):
            path += '/'
        for execluded_path in excluded_paths:
            if not execluded_path.endswith('/'):
                execluded_path += '/'
            if path == execluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Retrieves the authorization header from the request.

        Args:
            request (flask.Request, optional): The request object.
            Defaults to None.

        Returns:
            str: The authorization header if present,
            None otherwise.
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves the current user from the request.

        Args:
            request (flask.Request, optional): The request object.
            Defaults to None.

        Returns:
            TypeVar('User'): The current user,
            or None if no user is authenticated.
        """
        return None
