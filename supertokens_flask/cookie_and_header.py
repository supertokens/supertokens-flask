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
    ACCESS_TOKEN_COOKIE_KEY,
    REFRESH_TOKEN_COOKIE_KEY,
    ANTI_CSRF_HEADER_SET_KEY,
    ANTI_CSRF_HEADER_GET_KEY,
    ID_REFRESH_TOKEN_COOKIE_KEY,
    ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_EXPOSE_HEADERS,
    ID_REFRESH_TOKEN_HEADER_SET_KEY,
    ACCESS_CONTROL_ALLOW_CREDENTIALS,
    SUPERTOKENS_SDK_NAME_HEADER_GET_KEY,
    SUPERTOKENS_SDK_NAME_HEADER_SET_KEY,
    SUPERTOKENS_SDK_VERSION_HEADER_GET_KEY,
    SUPERTOKENS_SDK_VERSION_HEADER_SET_KEY
)
from supertokens_flask.device_info import DeviceInfo
from supertokens_flask.handshake_info import HandshakeInfo
from urllib.parse import quote, unquote


def save_frontend_info_from_request(request):
    try:
        name = get_header(request, SUPERTOKENS_SDK_NAME_HEADER_GET_KEY)
        version = get_header(request, SUPERTOKENS_SDK_VERSION_HEADER_GET_KEY)
        if name is not None and version is not None:
            DeviceInfo.get_instance().add_to_frontend_sdk({
                'name': name,
                'version': version
            })
    except Exception:
        pass


def set_options_api_headers(response):
    set_header(
        response,
        ACCESS_CONTROL_ALLOW_HEADERS,
        ANTI_CSRF_HEADER_SET_KEY)
    set_header(response, ACCESS_CONTROL_ALLOW_HEADERS,    # TODO: use from constants.py file? -- OKAY, changed
               SUPERTOKENS_SDK_NAME_HEADER_SET_KEY)
    set_header(response, ACCESS_CONTROL_ALLOW_HEADERS,
               SUPERTOKENS_SDK_VERSION_HEADER_SET_KEY)
    set_header(response, ACCESS_CONTROL_ALLOW_CREDENTIALS, 'true')


def set_header(response, key, value):
    existing_value = response.headers.get(key)
    if existing_value is not None:
        value = existing_value + ", " + value
    response.headers[key] = value


def get_header(request, key):
    return request.headers.get(key)


def get_cookie(request, key):
    cookie_val = request.cookies.get(key)
    if cookie_val is None:
        return None
    return unquote(cookie_val)


# TODO: ceil expires instead of flooring it. -- DONE
def set_cookie(response, key, value, expires, path,
               domain, secure, http_only, same_site):
    response.set_cookie(key=key, value=quote(value, encoding='utf-8'), expires=expires // 1000, path=path,
                        domain=domain, secure=secure, httponly=http_only, samesite=same_site)


def attach_anti_csrf_header(response, value):
    set_header(response, ANTI_CSRF_HEADER_SET_KEY, value)
    set_header(
        response,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ANTI_CSRF_HEADER_SET_KEY)


def get_anti_csrf_header(request):
    return get_header(request, ANTI_CSRF_HEADER_GET_KEY)


def attach_access_token_to_cookie(
        response, token, expires_at, domain, path, secure, same_site):
    set_cookie(response, ACCESS_TOKEN_COOKIE_KEY, token, expires_at, path,
               domain, secure, True, same_site)


def attach_refresh_token_to_cookie(
        response, token, expires_at, domain, path, secure, same_site):
    set_cookie(response, REFRESH_TOKEN_COOKIE_KEY, token, expires_at, path,
               domain, secure, True, same_site)


def attach_id_refresh_token_to_cookie_and_header(
        response, token, expires_at, domain, path, secure, same_site):
    set_header(
        response,
        ID_REFRESH_TOKEN_HEADER_SET_KEY,
        token +
        ';' +
        str(expires_at))
    set_header(
        response,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ID_REFRESH_TOKEN_HEADER_SET_KEY)
    set_cookie(response, ID_REFRESH_TOKEN_COOKIE_KEY, token, expires_at, path,
               domain, secure, True, same_site)


def get_access_token_from_cookie(request):
    return get_cookie(request, ACCESS_TOKEN_COOKIE_KEY)


def get_refresh_token_from_cookie(request):
    return get_cookie(request, REFRESH_TOKEN_COOKIE_KEY)


def get_id_refresh_token_from_cookie(request):
    return get_cookie(request, ID_REFRESH_TOKEN_COOKIE_KEY)


def clear_cookies(response):  # TODO: this is OK, but why do you need to have two functions for clearing session?
    # This one and the one above. -- Above function removed
    if response is not None:
        handshake_info = HandshakeInfo.get_instance()
        domain = handshake_info.cookie_domain
        secure = handshake_info.cookie_secure
        access_token_path = handshake_info.access_token_path
        refresh_token_path = handshake_info.refresh_token_path
        id_refresh_token_path = handshake_info.id_refresh_token_path
        same_site = handshake_info.same_site
        set_cookie(response, ACCESS_TOKEN_COOKIE_KEY, '', 0, access_token_path,
                   domain, secure, True, same_site)
        set_cookie(response, ID_REFRESH_TOKEN_COOKIE_KEY, '', 0,
                   id_refresh_token_path, domain, secure, True, same_site)
        set_cookie(response, REFRESH_TOKEN_COOKIE_KEY, '', 0, refresh_token_path,
                   domain, secure, True, same_site)
        set_header(response, ID_REFRESH_TOKEN_HEADER_SET_KEY, "remove")
        set_header(
            response,
            ACCESS_CONTROL_EXPOSE_HEADERS,  # TODO: shouldn't you use ACCESS_CONTROL_EXPOSE_HEADERS? -- DONE
            ID_REFRESH_TOKEN_HEADER_SET_KEY)
