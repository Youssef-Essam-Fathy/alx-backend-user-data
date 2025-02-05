#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None
auth_type = getenv('AUTH_TYPE')
if auth_type == "auth":
    from api.v1.auth.auth import Auth
    auth = Auth()
if auth_type == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()


@app.before_request
def before_request() -> None:
    """Method to handle authentication
    and authorization before each request.

    This method ensures that each request is properly
    authenticated and authorized before proceeding.
    It performs the following checks:

    1. If `auth` is None, the function returns immediately,
    allowing the request to proceed.
    2. If the request path is not in the list of excluded paths,
    the function proceeds with authorization checks.
    3. If the `Authorization` header is missing from the request,
    a 401 Unauthorized response is returned.
    4. If the current user cannot be identified from the request,
    a 403 Forbidden response is returned.

    The list of excluded paths allows certain endpoints
    to be accessible without authentication.

    Returns:
        None
    """
    if auth is None:
        return
    if not auth.require_auth(
        request.path,
        ['/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/']
    ):
        return
    if auth.authorization_header(request) is None:
        abort(401)
    if auth.current_user(request) is None:
        abort(403)


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(e) -> str:
    """ Unauthorized handler
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(e) -> str:
    """ Forbidden handler
    """
    return jsonify({"error": "Forbidden"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
