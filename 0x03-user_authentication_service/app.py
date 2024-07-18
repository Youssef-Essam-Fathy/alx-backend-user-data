#!/usr/bin/env python3
"""
Basic Flask Module
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)

AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def main():
    """ Main route
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """ Users route
    """
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """ Login route
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        abort(400)

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """ Logout route
    """
    if request.method == 'DELETE':
        session_id = request.cookies.get('session_id')
        user = AUTH.get_user_from_session_id(session_id)

        if user:
            AUTH.destroy_session(user.id)
            response = redirect('/')
            response.set_cookie('session_id', '', expires=0)
            return response
        else:
            abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
