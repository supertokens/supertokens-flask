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

from base64 import b64encode, b64decode
from time import time


def utf_base64encode(s):
    return b64encode(s.encode('utf-8')).decode('utf-8')


def utf_base64decode(s):
    return b64decode(s.encode('utf-8')).decode('utf-8')


def find_max_version(versions_1, versions_2):
    versions = list(set(versions_1) & set(versions_2))
    if len(versions) == 0:
        return None

    max_v = versions[0]
    for i in range(1, len(versions)):
        version = versions[i]
        max_v = compare_version(max_v, version)

    return max_v


def compare_version(v1, v2):
    v1_split = v1.split('.')
    v2_split = v2.split('.')
    max_loop = min(len(v1_split), len(v2_split))

    for i in range(max_loop):
        if int(v1_split[i]) > int(v2_split[i]):
            return v1
        elif int(v2_split[i]) > int(v1_split[i]):
            return v2

    if len(v1_split) > len(v2_split):
        return v1

    return v2


def is_4xx_error(status_code):
    return status_code // 100 == 4


def is_5xx_error(status_code):
    return status_code // 100 == 5


def sanitize_string(s):
    if s == "":
        return s

    if not isinstance(s, str):
        return None

    return s.strip()


def sanitize_number(n):
    _type = type(n)
    if _type == int or _type == float:
        return n

    return None


def get_timestamp_ms():
    return int(time() * 1000)
