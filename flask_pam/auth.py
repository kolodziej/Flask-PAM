# -*- coding: utf-8 -*-

import simplepam
import grp
import pwd
import functools
import logging
from datetime import datetime, timedelta
from flask import request, abort

logger = logging.getLogger('flask.ext.flask_pam')

class Auth:
    """Plugin for Flask which implements PAM authentication with tokens."""

    def __init__(self, token_storage_type, token_type, app = None):
        """Initialization of Auth object
        
        :param token_storage_type: type which derives from
        token_storage.TokenStorage

        :param token_type: type which derives from token.Token

        :param app: Flask class' instance
        """
        self.token_type = token_type
        self.token_storage = token_storage_type()
        self.init_app(app)

    def init_app(self, app):
        """Saves Flask class' instance in self.app

        :param app: Flask class' instance
        """
        self.app = app

    def authenticate(self, username, password):
        """This function calls simplepam's authenticate function and returns
        status of authentication using PAM and token object (of type
        self.token_type)

        :param username: username in Linux

        :param password: password for username
        """
        if simplepam.authenticate(username, password):
            logger.debug("user " + username + " authenticated")
            expire = datetime.now() + timedelta(minutes=30)
            token = self.token_type(request, username, expire)
            self.token_storage.set(token)
            return (True, token)

        logger.debug("authentication failed")
        return (False, None)

    def authenticated(self, user_token):
        """Checks if user is authenticated using token passed in argument
        user_token.

        :param user_token: string representing token
        """
        token = self.token_storage.get(user_token)
        if token and token.validate(user_token):
            logger.debug("user has a valid token")
            return True

        logger.debug("user has invalid token")
        return False

    def group_authenticated(self, user_token, group):
        """Checks if user represented by token is in group.

        :param user_token: string representing token

        :param group: group's name
        """
        if self.authenticated(user_token):
            token = self.token_storage.get(user_token)
            groups = self.get_groups(token.username)
            if group in groups:
                logger.info("user is in group " + group)
                return True

        return False

    def get_groups(self, username):
        """Returns list of groups in which user is.

        :param username: name of Linux user
        """
        groups = []
        for group in grp.getgrall():
            if username in group.gr_mem:
                logger.info("user " + username + " is in group " + group.gr_name)
                groups.append(group.gr_name)

        return groups

    # decorators
    def auth_required(self, view):
        """Decorator for Flask's view which blocks not authenticated requests

        :param view: Flask's view function
        """
        @functools.wraps(view)
        def decorated(*args, **kwargs):
            logger.info("running view which requires Flask-PAM authentication")
            if request.method == 'POST':
                token = request.form['token']
                if self.authenticated(token):
                    return view(*args, **kwargs)

            return abort(403)

        return decorated

    def group_required(self, group):
        """Decorator for Flask's view which blocks requests from not
        authenticated users or if user is not member of specified group

        :param group: group's name
        """
        def decorator(view):
            @functools.wraps(view)
            def decorated(*args, **kwargs):
                logger.info("running view which requires being a member of group " + group)
                if request.method == 'POST':
                    token = request.form['token']
                    if self.group_authenticated(token, group):
                        return view(*args, **kwargs)
                
                logger.warning("user has no access to view due to not being a member of group " + group)
                return abort(403)

            return decorated
        return decorator
