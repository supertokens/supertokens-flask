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

from flask import (
    Flask, request, g, jsonify, make_response, render_template
)
from supertokens_flask import (
    handshake_info,
    supertokens_middleware,
    revoke_all_sessions_for_user,
    SuperTokens, create_new_session,
    set_relevant_headers_for_options_api
)
from json import dumps

app = Flask(__name__, static_url_path='')
app.config['SUPERTOKENS_HOSTS'] = [{'hostname': '127.0.0.1', 'port': 9000}]
supertokens = SuperTokens(app)


def try_refresh_token(e):
    response = make_response(jsonify({'error': 'try refresh token'}), 440)
    attach_credentials_headers(response)
    return response


def unauthorised(e):
    response = make_response(jsonify({'error': 'unauthorised'}), 440)
    attach_credentials_headers(response)
    return response


supertokens.set_try_refresh_token_error_handler(try_refresh_token)
supertokens.set_unauthorised_error_handler(unauthorised)


class Test:
    no_of_times_refresh_called_during_test = 0
    no_of_times_get_session_called_during_test = 0

    @staticmethod
    def reset():
        handshake_info.HandshakeInfo.reset()
        Test.no_of_times_refresh_called_during_test = 0
        Test.no_of_times_get_session_called_during_test = 0

    @staticmethod
    def increment_refresh():
        Test.no_of_times_refresh_called_during_test += 1

    @staticmethod
    def increment_get_session():
        Test.no_of_times_get_session_called_during_test += 1

    @staticmethod
    def get_session_called_count():
        return Test.no_of_times_get_session_called_during_test

    @staticmethod
    def get_refresh_called_count():
        return Test.no_of_times_refresh_called_during_test


@app.route('/index.html')
def send_file():
    return render_template('index.html')


def send_options_api_response():
    response = make_response('', 200)
    response.headers['Access-Control-Allow-Origin'] = 'http://127.0.0.1:8080'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    set_relevant_headers_for_options_api(response)
    return response


def attach_credentials_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'http://127.0.0.1:8080'
    response.headers['Access-Control-Allow-Credentials'] = 'true'


@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    user_id = request.json['userId']
    response = make_response(user_id, 200)
    create_new_session(response, user_id)
    attach_credentials_headers(response)
    return response


@app.route('/beforeeach', methods=['POST'])
def before_each():
    Test.reset()
    return '', 200


@app.route('/testUserConfig', methods=['POST'])
def test_config():
    return '', 200


@app.route('/multipleInterceptors', methods=['POST', 'OPTIONS'])
def multiple_interceptors():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    result_bool = 'success' if 'interceptorheader2' in request.headers and 'interceptorheader1' in request.headers else 'failure'
    return result_bool, 200


@app.route('/', methods=['GET', 'OPTIONS'])
@supertokens_middleware(True)
def get_info():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    Test.increment_get_session()
    response = make_response(g.supertokens.get_user_id(), 200)
    attach_credentials_headers(response)
    response.headers['Cache-Control'] = 'no-cache, private'
    return response


@app.route('/update-jwt', methods=['GET', 'POST', 'OPTIONS'])
@supertokens_middleware(True)
def update_jwt():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    Test.increment_get_session()
    if request.method == 'POST':
        g.supertokens.update_jwt_payload(request.json)
    response = make_response(jsonify(g.supertokens.get_jwt_payload()), 200)
    attach_credentials_headers(response)
    response.headers['Cache-Control'] = 'no-cache, private'
    return response


@app.route('/testing', methods=['GET', 'OPTIONS', 'POST', 'DELETE', 'PUT'])
def testing():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    response = make_response('success', 200)
    if 'testing' in request.headers:
        response.headers['testing'] = request.headers['testing']
    return response


@app.route('/logout', methods=['POST', 'OPTIONS'])
@supertokens_middleware
def logout():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    response = make_response('success', 200)
    g.supertokens.revoke_session()
    attach_credentials_headers(response)
    return response


@app.route('/revokeAll', methods=['POST', 'OPTIONS'])
@supertokens_middleware(True)
def revoke_all():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    response = make_response('success', 200)
    revoke_all_sessions_for_user(g.supertokens.get_user_id())
    return response


@app.route('/refresh', methods=['POST', 'OPTIONS'])
@supertokens_middleware
def refresh():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    Test.increment_refresh()
    response = make_response('refresh success', 200)
    attach_credentials_headers(response)
    return response


@app.route('/refreshCalledTime', methods=['GET', 'OPTIONS'])
def get_refresh_called_info():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    response = make_response(dumps(Test.get_refresh_called_count()), 200)
    response.headers['Access-Control-Allow-Origin'] = 'http://127.0.0.1:8080'
    return response


@app.route('/getSessionCalledTime', methods=['GET', 'OPTIONS'])
def get_session_called_info():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    response = make_response(dumps(Test.get_session_called_count()), 200)
    response.headers['Access-Control-Allow-Origin'] = 'http://127.0.0.1:8080'
    return response


@app.route('/ping', methods=['GET', 'OPTIONS'])
def ping():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    return 'success', 200


@app.route('/testHeader', methods=['GET', 'OPTIONS'])
def test_header():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    success_info = request.headers.get('st-custom-header')
    return jsonify({'success': success_info})


@app.route('/checkDeviceInfo', methods=['GET', 'OPTIONS'])
def check_device_info():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    sdk_name = request.headers.get('supertokens-sdk-name')
    sdk_version = request.headers.get('supertokens-sdk-version')
    return 'true' if sdk_name == 'website' and type(sdk_version) == str else 'false'


@app.route('/checkAllowCredentials', methods=['GET', 'OPTIONS'])
def check_allow_credentials():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    return dumps('allow-credentials' in request.headers), 200


@app.route('/testError', methods=['GET', 'OPTIONS'])
def test_error():
    if request.method == 'OPTIONS':
        return send_options_api_response()
    return 'test error message', 500


@app.errorhandler(405)
def f_405(e):
    return '', 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
