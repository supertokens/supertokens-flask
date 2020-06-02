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

from .utils import (
    reset, setup_st, clean_st, start_st,
    extract_all_cookies,
    get_unix_timestamp
)
from supertokens_flask import (
    supertokens_middleware,
    create_new_session,
    SuperTokens
)
from pytest import fixture
from flask import request, Flask, jsonify, g, make_response


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@fixture(scope='function')
def app():
    app = Flask(__name__)
    supertokens = SuperTokens(app)

    def ff(e):
        return jsonify({'error_msg': 'try refresh token'}), 401
    supertokens.set_try_refresh_token_error_handler(ff)

    @app.route('/login')
    def login():
        user_id = 'userId'
        response = make_response(jsonify({'userId': user_id}), 200)
        create_new_session(response, user_id, {}, {})
        return response

    @app.route('/refresh', methods=['POST'])
    @supertokens_middleware
    def refresh():
        return {'userId': g.supertokens_session.get_user_id()}

    @app.route('/info', methods=['GET', 'OPTIONS'])
    @supertokens_middleware
    def info():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})

        return jsonify({'userId': g.supertokens_session.get_user_id()})

    @app.route('/logout', methods=['POST'])
    @supertokens_middleware()
    def logout():
        g.supertokens_session.revoke_session()
        return jsonify({'success': True})

    return app


def test_decorators_with_app(app):
    start_st()
    response_1 = app.test_client().get('/login')
    assert response_1.json == {'userId': 'userId'}
    assert response_1.status_code == 200
    cookies_1 = extract_all_cookies(response_1)

    request_2 = app.test_client()
    request_2.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_2.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    response_2 = request_2.get(
        '/info',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')})
    assert response_2.json == {'userId': 'userId'}
    assert response_2.status_code == 200

    request_3 = app.test_client()
    request_3.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_3 = request_3.post('/refresh')
    assert response_3.json == {'userId': 'userId'}
    assert response_3.status_code == 200
    cookies_3 = extract_all_cookies(response_3)
    assert cookies_1['sAccessToken']['value'] != cookies_3['sAccessToken']['value']
    assert cookies_1['sRefreshToken']['value'] != cookies_3['sRefreshToken']['value']
    assert cookies_1['sIdRefreshToken']['value'] != cookies_3['sIdRefreshToken']['value']
    assert response_3.headers.get('anti-csrf') is not None
    assert cookies_3['sAccessToken']['domain'] == 'supertokens.io'
    assert cookies_3['sRefreshToken']['domain'] == 'supertokens.io'
    assert cookies_3['sIdRefreshToken']['domain'] == 'supertokens.io'
    assert cookies_3['sAccessToken']['path'] == '/'
    assert cookies_3['sRefreshToken']['path'] == '/refresh'
    assert cookies_3['sIdRefreshToken']['path'] == '/'
    assert cookies_3['sAccessToken']['httponly']
    assert cookies_3['sRefreshToken']['httponly']
    assert cookies_3['sIdRefreshToken']['httponly']
    assert cookies_3['sAccessToken'].get('samesite') == 'None'
    assert cookies_3['sRefreshToken'].get('samesite') == 'None'
    assert cookies_3['sIdRefreshToken'].get('samesite') == 'None'
    assert cookies_3['sAccessToken'].get('secure') is None
    assert cookies_3['sRefreshToken'].get('secure') is None
    assert cookies_3['sIdRefreshToken'].get('secure') is None

    request_4 = app.test_client()
    request_4.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_3['sAccessToken']['value'])
    request_4.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_3['sIdRefreshToken']['value'])
    response_4 = request_4.get(
        '/info',
        headers={
            'anti-csrf': response_3.headers.get('anti-csrf')})
    assert response_4.json == {'userId': 'userId'}
    assert response_4.status_code == 200
    cookies_4 = extract_all_cookies(response_4)
    assert cookies_4['sAccessToken']['value'] != cookies_3['sAccessToken']['value']
    assert response_4.headers.get('anti-csrf') is None
    assert cookies_4.get('sRefreshToken') is None
    assert cookies_4.get('sIdRefreshToken') is None
    assert cookies_4['sAccessToken']['domain'] == 'supertokens.io'
    assert cookies_4['sAccessToken']['path'] == '/'
    assert cookies_4['sAccessToken']['httponly']
    assert cookies_4['sAccessToken'].get('samesite') == 'None'
    assert cookies_4['sAccessToken'].get('secure') is None

    response_5 = app.test_client().options('/info')
    assert response_5.json == {'method': 'option'}
    assert response_5.status_code == 200

    request_6 = app.test_client()
    request_6.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_4['sAccessToken']['value'])
    request_6.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_3['sIdRefreshToken']['value'])
    response_6 = request_6.get(
        '/info',
        headers={
            'anti-csrf': response_3.headers.get('anti-csrf')})
    assert response_6.json == {'userId': 'userId'}
    assert response_6.status_code == 200

    response_7 = app.test_client().get('/info')
    assert response_7.json == {'error_msg': 'try refresh token'}
    assert response_7.status_code == 401

    request_8 = app.test_client()
    request_8.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_8 = request_8.post('/refresh')
    assert response_8.json == {'error': 'token theft detected'}
    assert response_8.status_code == 440
    cookies_8 = extract_all_cookies(response_8)
    assert cookies_8['sAccessToken']['value'] == ''
    assert cookies_8['sRefreshToken']['value'] == ''
    assert cookies_8['sIdRefreshToken']['value'] == ''
    assert get_unix_timestamp(cookies_8['sAccessToken']['expires']) == 0
    assert get_unix_timestamp(cookies_8['sRefreshToken']['expires']) == 0
    assert get_unix_timestamp(cookies_8['sIdRefreshToken']['expires']) == 0

    response_9 = app.test_client().get('/login')
    cookies_9 = extract_all_cookies(response_9)

    request_10 = app.test_client()
    request_10.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_9['sAccessToken']['value'])
    request_10.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_9['sIdRefreshToken']['value'])
    response_10 = request_10.post(
        '/logout',
        headers={
            'anti-csrf': response_9.headers.get('anti-csrf')})
    assert response_10.json == {'success': True}
    assert response_10.status_code == 200

    request_11 = app.test_client()
    request_11.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_9['sRefreshToken']['value'])
    response_11 = request_11.post('/refresh')
    assert response_11.json == {'error': 'unauthorised'}
    assert response_11.status_code == 440
    cookies_11 = extract_all_cookies(response_11)
    assert cookies_11['sAccessToken']['value'] == ''
    assert cookies_11['sRefreshToken']['value'] == ''
    assert cookies_11['sIdRefreshToken']['value'] == ''
    assert get_unix_timestamp(cookies_11['sAccessToken']['expires']) == 0
    assert get_unix_timestamp(cookies_11['sRefreshToken']['expires']) == 0
    assert get_unix_timestamp(cookies_11['sIdRefreshToken']['expires']) == 0
