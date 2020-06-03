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
from supertokens_flask import session_helper
from supertokens_flask.constants import SESSION_REGENERATE
from supertokens_flask.cookie_and_header import clear_cookies, attach_access_token_to_cookie
from supertokens_flask.exceptions import SuperTokensUnauthorisedError, raise_unauthorised_exception
from supertokens_flask.querier import Querier


class Session:
    def __init__(self, access_token, session_handle,
                 user_id, jwt_payload, response):
        self.__access_token = access_token
        self.__session_handle = session_handle
        self.__user_id = user_id
        self.__jwt_payload = jwt_payload
        self.__response = response
        self.new_access_token_info = None
        self.new_refresh_token_info = None
        self.new_id_refresh_token_info = None
        self.new_anti_csrf_token = None
        self.remove_cookies = False

    def __clear_cookies(self):
        clear_cookies(self.__response)

    def revoke_session(self):
        if session_helper.revoke_session(self.__session_handle):
            if self.__response is not None:
                self.__clear_cookies()
            else:
                self.remove_cookies = True

    def get_session_data(self):
        try:
            return session_helper.get_session_data(self.__session_handle)
        except SuperTokensUnauthorisedError as e:
            self.__clear_cookies()
            raise e

    def update_session_data(self, new_session_data):
        try:
            return session_helper.update_session_data(
                self.__session_handle, new_session_data)
        except SuperTokensUnauthorisedError as e:
            self.__clear_cookies()
            raise e

    def update_jwt_payload(self, new_jwt_payload):
        result = Querier.get_instance().send_post_request(SESSION_REGENERATE, {
            'accessToken': self.__access_token,
            'userDataInJWT': new_jwt_payload
        })
        if result['status'] == 'UNAUTHORISED':
            self.__clear_cookies()
            raise_unauthorised_exception(result['message'])
        self.__jwt_payload = result['session']['userDataInJWT']
        if 'accessToken' in result and result['accessToken'] is not None:
            self.__access_token = result['accessToken']['token']
            if self.__response is None:
                self.new_access_token_info = result['accessToken']
            else:
                attach_access_token_to_cookie(
                    self.__response,
                    result['access_token']['token'],
                    result['access_token']['expiry'],
                    result['access_token']['domain'],
                    result['access_token']['cookiePath'],
                    result['access_token']['cookieSecure'],
                    result['access_token']['sameSite']
                )

    def get_user_id(self):
        return self.__user_id

    def get_jwt_payload(self):
        return self.__jwt_payload

    def get_handle(self):
        return self.__session_handle

    def get_access_token(self):
        return self.__access_token
