"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from functools import wraps
from flask import make_response, request, g
from supertokens_flask.supertokens import get_session, refresh_session
from supertokens_flask.cookie_and_header import (
    clear_cookies,
    attach_access_token_to_cookie,
    attach_anti_csrf_header,
    attach_id_refresh_token_to_cookie_and_header,
    attach_refresh_token_to_cookie
)
from supertokens_flask.handshake_info import HandshakeInfo
from supertokens_flask.cookie_and_header import CookieConfig


def __manage_cookies_post_response(session, response):
    if session.remove_cookies:
        clear_cookies(response)
    else:
        access_token = session.new_access_token_info
        if access_token is not None:
            attach_access_token_to_cookie(
                response,
                access_token['token'],
                access_token['expiry'],
                access_token['domain'] if 'domain' in access_token else None,
                access_token['cookiePath'],
                access_token['cookieSecure'],
                access_token['sameSite']
            )
        refresh_token = session.new_refresh_token_info
        if refresh_token is not None:
            attach_refresh_token_to_cookie(
                response,
                refresh_token['token'],
                refresh_token['expiry'],
                refresh_token['domain'] if 'domain' in refresh_token else None,
                refresh_token['cookiePath'],
                refresh_token['cookieSecure'],
                refresh_token['sameSite']
            )
        id_refresh_token = session.new_id_refresh_token_info
        if id_refresh_token is not None:
            attach_id_refresh_token_to_cookie_and_header(
                response,
                id_refresh_token['token'],
                id_refresh_token['expiry'],
                id_refresh_token['domain'] if 'domain' in id_refresh_token else None,
                id_refresh_token['cookiePath'],
                id_refresh_token['cookieSecure'],
                id_refresh_token['sameSite']
            )
        anti_csrf_token = session.new_anti_csrf_token
        if anti_csrf_token is not None:
            attach_anti_csrf_header(response, anti_csrf_token)


def supertokens_middleware(anti_csrf_check=None):
    def session_verify(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            if request.method in {'OPTIONS', 'TRACE'}:
                return f(*args, **kwargs)
            if anti_csrf_check is None:
                do_anti_csrf_check = request.method != 'GET'
            else:
                do_anti_csrf_check = anti_csrf_check

            refresh_path = HandshakeInfo.get_instance().refresh_token_path
            if CookieConfig.get_instance().refresh_token_path is not None:
                refresh_path = CookieConfig.get_instance().refresh_token_path
            if request.path in (refresh_path, refresh_path + '/', '/' + refresh_path + '/' + refresh_path + '/') and \
                    request.method == 'POST':
                session = refresh_session(None)
                g.supertokens = session
                response = make_response(f(*args, **kwargs))
                __manage_cookies_post_response(session, response)
                return response

            session = get_session(None, do_anti_csrf_check)
            g.supertokens = session
            response = make_response(f(*args, **kwargs))
            __manage_cookies_post_response(session, response)
            return response
        return wrapped_function
    if callable(anti_csrf_check):
        func = anti_csrf_check
        anti_csrf_check = None
        return session_verify(func)
    return session_verify
