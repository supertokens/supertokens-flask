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
    SESSION,
    VERSION,
    HANDSHAKE,
    API_VERSION,
    DEFAULT_HOSTS,
    SESSION_VERIFY,
    SESSION_REFRESH,
    API_VERSION_HEADER,
    API_KEY_HEADER,
    SUPPORTED_CDI_VERSIONS
)
from supertokens_flask.utils import (
    is_4xx_error,
    is_5xx_error,
    find_max_version
)
from supertokens_flask.exceptions import (
    raise_general_exception
)
from supertokens_flask.device_info import (
    DeviceInfo
)
import requests
from json import JSONDecodeError
from os import environ
from threading import Lock


class Querier:
    __instance = None
    __lock = Lock()

    def __init__(self, hosts=None, api_key=None):
        if hosts is None:
            hosts = DEFAULT_HOSTS
        self.__hosts = [host[:-1] if host[-1] == '/' else host for host in hosts.split(';')]
        self.__api_version = None
        self.__last_tried_index = 0
        self.__hosts_alive_for_testing = set()
        self.__api_key = api_key

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                'calling testing function in non testing env')
        Querier.__instance = None

    def get_hosts_alive_for_testing(self):
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                'calling testing function in non testing env')
        return self.__hosts_alive_for_testing

    def get_api_version(self):
        if self.__api_version is not None:
            return self.__api_version

        with Querier.__lock:
            if self.__api_version is not None:
                return self.__api_version

            def f(url):
                return requests.get(url, headers={
                    API_KEY_HEADER: self.__api_key
                })

            response = self.__send_request_helper(
                API_VERSION, 'GET', f, len(self.__hosts))
            cdi_supported_by_server = response['versions']
            api_version = find_max_version(
                cdi_supported_by_server,
                SUPPORTED_CDI_VERSIONS)

            if api_version is None:
                raise_general_exception('The running SuperTokens core version is not compatible with this Flask SDK. '
                                        'Please visit https://supertokens.io/docs/community/compatibility to find the '
                                        'right versions')

            self.__api_version = api_version
            return self.__api_version

    @staticmethod
    def get_instance():
        if Querier.__instance is None:
            with Querier.__lock:
                if Querier.__instance is None:
                    Querier.__instance = Querier()
        return Querier.__instance

    @staticmethod
    def init_instance(hosts, api_key):
        if Querier.__instance is None:
            Querier.__instance = Querier(hosts, api_key)

    def send_get_request(self, path, params=None):
        if params is None:
            params = {}

        def f(url):
            return requests.get(url, params=params, headers={
                API_VERSION_HEADER: self.get_api_version(),
                API_KEY_HEADER: self.__api_key
            })

        return self.__send_request_helper(path, 'GET', f, len(self.__hosts))

    def send_post_request(self, path, data=None, test=False):
        if data is None:
            data = {}

        if path in {SESSION, SESSION_VERIFY, SESSION_REFRESH, HANDSHAKE}:
            data['deviceDriverInfo'] = {
                'frontendSDK': DeviceInfo.get_instance().get_frontend_sdk(),
                'driver': {
                    'name': 'flask',
                    'version': VERSION
                }
            }

        if ('SUPERTOKENS_ENV' in environ) and (
                environ['SUPERTOKENS_ENV'] == 'testing') and test:
            return data

        def f(url):
            return requests.post(url, json=data, headers={
                API_VERSION_HEADER: self.get_api_version(),
                API_KEY_HEADER: self.__api_key
            })

        return self.__send_request_helper(path, 'POST', f, len(self.__hosts))

    def send_delete_request(self, path, data=None):
        if data is None:
            data = {}

        def f(url):
            return requests.delete(url, json=data, headers={
                API_VERSION_HEADER: self.get_api_version(),
                API_KEY_HEADER: self.__api_key
            })

        return self.__send_request_helper(path, 'DELETE', f, len(self.__hosts))

    def send_put_request(self, path, data=None):
        if data is None:
            data = {}

        def f(url):
            return requests.put(url, json=data, headers={
                API_VERSION_HEADER: self.get_api_version(),
                API_KEY_HEADER: self.__api_key
            })

        return self.__send_request_helper(path, 'PUT', f, len(self.__hosts))

    def __send_request_helper(self, path, method, http_function, no_of_tries):
        if no_of_tries == 0:
            raise_general_exception('No SuperTokens core available to query')

        try:
            current_host = self.__hosts[self.__last_tried_index]
            self.__last_tried_index += 1
            self.__last_tried_index %= len(self.__hosts)
            url = current_host + path
            response = http_function(url)

            if ('SUPERTOKENS_ENV' in environ) and (
                    environ['SUPERTOKENS_ENV'] == 'testing'):
                self.__hosts_alive_for_testing.add(current_host)

            if is_4xx_error(response.status_code) or is_5xx_error(response.status_code):
                raise_general_exception('SuperTokens core threw an error for a ' + method + ' request to path: ' +
                                        path + ' with status code: ' + str(response.status_code) + ' and message: ' +
                                        response.text)

            try:
                return response.json()
            except JSONDecodeError:
                return response.text

        except requests.exceptions.ConnectionError:
            return self.__send_request_helper(
                path, method, http_function, no_of_tries - 1)

        except Exception as e:
            raise_general_exception(e)
