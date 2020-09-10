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

from supertokens_flask.constants import (
    HOSTS_CONFIG,
    API_CONFIG,
    ACCESS_TOKEN_PATH_CONFIG,
    REFRESH_TOKEN_PATH_CONFIG,
    COOKIE_DOMAIN_CONFIG,
    COOKIE_SECURE_CONFIG,
    COOKIE_SAME_SITE_CONFIG
)
from supertokens_flask.exceptions import (
    raise_try_refresh_token_exception,
    raise_unauthorised_exception,
    SuperTokensTokenTheftError,
    SuperTokensUnauthorisedError,
    SuperTokensTryRefreshTokenError,
)
from supertokens_flask.session import Session
from flask import request, make_response
from supertokens_flask import session_helper
from supertokens_flask.cookie_and_header import (
    CookieConfig,
    clear_cookies,
    get_anti_csrf_header,
    attach_anti_csrf_header,
    set_options_api_headers,
    get_access_token_from_cookie,
    attach_access_token_to_cookie,
    get_refresh_token_from_cookie,
    attach_refresh_token_to_cookie,
    save_frontend_info_from_request,
    get_id_refresh_token_from_cookie,
    attach_id_refresh_token_to_cookie_and_header,
    get_cors_allowed_headers as get_cors_allowed_headers_from_cookie_and_headers
)
from supertokens_flask.default_callbacks import (
    default_unauthorised_callback,
    default_try_refresh_token_callback,
    default_token_theft_detected_callback
)


def create_new_session(response, user_id, jwt_payload=None, session_data=None):
    session = session_helper.create_new_session(
        user_id, jwt_payload, session_data)
    access_token = session['accessToken']
    refresh_token = session['refreshToken']
    id_refresh_token = session['idRefreshToken']
    attach_access_token_to_cookie(
        response,
        access_token['token'],
        access_token['expiry'],
        access_token['domain'] if 'domain' in access_token else None,
        access_token['cookiePath'],
        access_token['cookieSecure'],
        access_token['sameSite']
    )
    attach_refresh_token_to_cookie(
        response,
        refresh_token['token'],
        refresh_token['expiry'],
        refresh_token['domain'] if 'domain' in refresh_token else None,
        refresh_token['cookiePath'],
        refresh_token['cookieSecure'],
        refresh_token['sameSite']
    )
    attach_id_refresh_token_to_cookie_and_header(
        response,
        id_refresh_token['token'],
        id_refresh_token['expiry'],
        id_refresh_token['domain'] if 'domain' in id_refresh_token else None,
        id_refresh_token['cookiePath'],
        id_refresh_token['cookieSecure'],
        id_refresh_token['sameSite']
    )
    if 'antiCsrfToken' in session and session['antiCsrfToken'] is not None:
        attach_anti_csrf_header(response, session['antiCsrfToken'])

    return Session(access_token['token'], session['session']['handle'], session['session']['userId'],
                   session['session']['userDataInJWT'], response)


def get_session(response, enable_csrf_protection):
    save_frontend_info_from_request(request)
    id_refresh_token = get_id_refresh_token_from_cookie(request)
    if id_refresh_token is None:
        clear_cookies(response)
        raise_unauthorised_exception('id refresh token is missing in cookies')
    access_token = get_access_token_from_cookie(request)
    if access_token is None:
        raise_try_refresh_token_exception('access token missing in cookies')
    try:
        anti_csrf_token = get_anti_csrf_header(request)
        new_session = session_helper.get_session(access_token, anti_csrf_token, enable_csrf_protection)
        if 'accessToken' in new_session:
            access_token = new_session['accessToken']['token']

        session = Session(access_token, new_session['session']['handle'], new_session['session']['userId'],
                          new_session['session']['userDataInJWT'], response)

        if 'accessToken' in new_session:
            if response is not None:
                access_token_info = new_session['accessToken']
                attach_access_token_to_cookie(
                    response,
                    access_token_info['token'],
                    access_token_info['expiry'],
                    access_token_info['domain'] if 'domain' in access_token_info else None,
                    access_token_info['cookiePath'],
                    access_token_info['cookieSecure'],
                    access_token_info['sameSite']
                )
            else:
                session.new_access_token_info = new_session['accessToken']
        return session
    except SuperTokensUnauthorisedError as e:
        clear_cookies(response)
        raise e


def refresh_session(response):
    save_frontend_info_from_request(request)
    refresh_token = get_refresh_token_from_cookie(request)
    if refresh_token is None:
        clear_cookies(response)
        raise_unauthorised_exception('Missing auth tokens in cookies. Have you set the correct refresh API path in '
                                     'your frontend and SuperTokens config?')
    try:
        anti_csrf_token = get_anti_csrf_header(request)
        new_session = session_helper.refresh_session(refresh_token, anti_csrf_token)
        access_token = new_session['accessToken']
        refresh_token = new_session['refreshToken']
        id_refresh_token = new_session['idRefreshToken']
        session = Session(access_token['token'], new_session['session']['handle'], new_session['session']['userId'],
                          new_session['session']['userDataInJWT'], response)
        if response is not None:
            attach_access_token_to_cookie(
                response,
                access_token['token'],
                access_token['expiry'],
                access_token['domain'] if 'domain' in access_token else None,
                access_token['cookiePath'],
                access_token['cookieSecure'],
                access_token['sameSite']
            )
            attach_refresh_token_to_cookie(
                response,
                refresh_token['token'],
                refresh_token['expiry'],
                refresh_token['domain'] if 'domain' in refresh_token else None,
                refresh_token['cookiePath'],
                refresh_token['cookieSecure'],
                refresh_token['sameSite']
            )
            attach_id_refresh_token_to_cookie_and_header(
                response,
                id_refresh_token['token'],
                id_refresh_token['expiry'],
                id_refresh_token['domain'] if 'domain' in id_refresh_token else None,
                id_refresh_token['cookiePath'],
                id_refresh_token['cookieSecure'],
                id_refresh_token['sameSite']
            )
            if 'antiCsrfToken' in new_session and new_session['antiCsrfToken'] is not None:
                attach_anti_csrf_header(response, new_session['antiCsrfToken'])
        else:
            session.new_access_token_info = access_token
            session.new_refresh_token_info = refresh_token
            session.new_id_refresh_token_info = id_refresh_token
            if 'antiCsrfToken' in new_session and new_session['antiCsrfToken'] is not None:
                session.new_anti_csrf_token = new_session['antiCsrfToken']
        return session
    except (SuperTokensTokenTheftError, SuperTokensUnauthorisedError) as e:
        clear_cookies(response)
        raise e


def revoke_session(session_handle):
    return session_helper.revoke_session(session_handle)


def revoke_all_sessions_for_user(user_id):
    return session_helper.revoke_all_sessions_for_user(user_id)


def get_all_session_handles_for_user(user_id):
    return session_helper.get_all_session_handles_for_user(user_id)


def revoke_multiple_sessions(session_handles):
    return session_helper.revoke_multiple_sessions(session_handles)


def get_session_data(session_handle):
    return session_helper.get_session_data(session_handle)


def update_session_data(session_handle, new_session_data):
    session_helper.update_session_data(session_handle, new_session_data)


def get_jwt_payload(session_handle):
    return session_helper.get_jwt_payload(session_handle)


def update_jwt_payload(session_handle, new_jwt_payload):
    session_helper.update_jwt_payload(session_handle, new_jwt_payload)


def set_relevant_headers_for_options_api(response):
    set_options_api_headers(response)


def get_cors_allowed_headers():
    return get_cors_allowed_headers_from_cookie_and_headers()


class SuperTokens:
    def __init__(self, app):
        self.__unauthorised_callback = default_unauthorised_callback
        self.__try_refresh_token_callback = default_try_refresh_token_callback
        self.__token_theft_detected_callback = default_token_theft_detected_callback
        hosts = app.config.setdefault(HOSTS_CONFIG, None)
        api_key = app.config.setdefault(API_CONFIG, None)
        access_token_path = app.config.setdefault(ACCESS_TOKEN_PATH_CONFIG, None)
        refresh_token_path = app.config.setdefault(REFRESH_TOKEN_PATH_CONFIG, None)
        cookie_domain = app.config.setdefault(COOKIE_DOMAIN_CONFIG, None)
        cookie_secure = app.config.setdefault(COOKIE_SECURE_CONFIG, None)
        cookie_same_site = app.config.setdefault(COOKIE_SAME_SITE_CONFIG, None)

        session_helper.init(hosts, api_key)
        CookieConfig.init(access_token_path, refresh_token_path, cookie_domain, cookie_secure, cookie_same_site)
        self.__set_error_handler_callbacks(app)

    def __set_error_handler_callbacks(self, app):
        @app.errorhandler(SuperTokensUnauthorisedError)
        def handle_unauthorised(e):
            response = make_response(self.__unauthorised_callback(e))
            clear_cookies(response)
            return response

        @app.errorhandler(SuperTokensTryRefreshTokenError)
        def handle_try_refresh_token(e):
            response = make_response(self.__try_refresh_token_callback(e))
            return response

        @app.errorhandler(SuperTokensTokenTheftError)
        def handle_token_theft(e):
            response = make_response(
                self.__token_theft_detected_callback(
                    e.session_handle, e.user_id))
            clear_cookies(response)
            return response

    def set_unauthorised_error_handler(self, callback):
        self.__unauthorised_callback = callback

    def set_try_refresh_token_error_handler(self, callback):
        self.__try_refresh_token_callback = callback

    def set_token_theft_detected_error_handler(self, callback):
        self.__token_theft_detected_callback = callback
