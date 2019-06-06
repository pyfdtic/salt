# -*- coding: utf-8 -*-
'''
A module that adds data to the Pillar structure retrieved by an http request


Configuring the HTTP_JSON ext_pillar
====================================

Set the following Salt config to setup http json result as external pillar source:

.. code-block:: yaml

  ext_pillar:
    - http_json:
        url: http://example.com/api/minion_id
        ::TODO::
        username: username
        password: password

If the with_grains parameter is set, grain keys wrapped in can be provided (wrapped
in <> brackets) in the url in order to populate pillar data based on the grain value.

.. code-block:: yaml

  ext_pillar:
    - http_json:
        url: http://example.com/api/<nodename>
        with_grains: True

.. versionchanged:: 2018.3.0

    If %s is present in the url, it will be automatically replaced by the minion_id:

    .. code-block:: yaml

        ext_pillar:
          - http_json:
              url: http://example.com/api/%s

Module Documentation
====================
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import logging
import re
import json

from salt.ext import six

# Import Salt libs
try:
    from salt.ext.six.moves.urllib.parse import quote as _quote

    _HAS_DEPENDENCIES = True
except ImportError:
    _HAS_DEPENDENCIES = False

# Set up logging
log = logging.getLogger(__name__)

"""
auth_type:
    basic
        username
        password
    token
        username
        password
        token_prefix
        auth_url
"""


class Auth(object):

    @classmethod
    def check_auth_properties(cls, auth_properties):
        # auth_properties 提供了 PARAMS 中所有参数, 且不为空,
        if all(auth_properties.values()) and \
            (set(cls.PARAMS) - set(
                auth_properties.keys()) == set()):
            return True

        log.error("auth_properties 不符合要求!! \n所需参数: [{}]\n 提供参数: {}".format(
            '|'.join(AuthBasic.PARAMS),
            json.dumps(auth_properties))
        )
        return False


class AuthBasic(Auth):
    NAME = 'basic'
    PARAMS = ('username', 'password')


class AuthToken(Auth):
    NAME = 'token'
    PARAMS = ('username', 'password', 'token_prefix', 'auth_url', 'token')


def __virtual__():
    return _HAS_DEPENDENCIES


def ext_pillar(minion_id,
               pillar,  # pylint: disable=W0613
               url,
               auth_type,
               auth_properties,
               with_grains=False):
    '''
    Read pillar data from HTTP response.

    :param str url: Url to request.
    :param bool with_grains: Whether to substitute strings in the url with their grain values.
    :param str auth_type: one of [basic, token]
    :param dict auth_properties:
        basic[username, password],
        token[username,password,token_prefix,auth_url]
    :return: A dictionary of the pillar data to add.
    :rtype: dict
    '''

    request_headers = {"Accept": "application/json, text/plain, */*",
                       "Content-Type": "application/json;charset=UTF-8"}

    url = url.replace('%s', _quote(minion_id))

    grain_pattern = r'<(?P<grain_name>.*?)>'

    if with_grains:
        # Get the value of the grain and substitute each grain
        # name for the url-encoded version of its grain value.
        for match in re.finditer(grain_pattern, url):
            grain_name = match.group('grain_name')
            grain_value = __salt__['grains.get'](grain_name, None)

            if not grain_value:
                log.error("Unable to get minion '%s' grain: %s", minion_id,
                          grain_name)
                return {}

            grain_value = _quote(six.text_type(grain_value))
            url = re.sub('<{0}>'.format(grain_name), grain_value, url)

    log.debug('Getting url: %s', url)

    # login to get token
    if auth_type == AuthBasic.NAME:
        if not AuthBasic.check_auth_properties(auth_properties):
            return {}

        data = __salt__['http.query'](url=url,
                                      username=auth_properties.get('username'),
                                      password=auth_properties.get('password'),
                                      decode=True,
                                      headers=request_headers,
                                      decode_type='json')

    elif auth_type == AuthToken.NAME:
        if not AuthToken.check_auth_properties(auth_properties):
            return {}

        auth_dict = dict(username=auth_properties.get('username'),
                         password=auth_properties.get('password'))

        token_data = __salt__['http.query'](
            url=auth_properties.get('auth_url'),
            method="POST",
            data=json.dumps(auth_dict),
            decode=True,
            decode_type='json')

        token = token_data.get('token')
        request_headers[auth_properties.get("token_prefix")] = token

        data = __salt__['http.query'](url=url,
                                      decode=True,
                                      headers=request_headers,
                                      decode_type='json')

    else:
        data = __salt__['http.query'](url=url, decode=True, decode_type='json')

    log.info("Pillar.http_json get data: --------------")
    log.info(data)
    log.info("-------------- End --------------")

    if 'dict' in data:
        return data['dict']

    log.error("Error on minion '%s' http query: %s\nMore Info:\n", minion_id,
              url)

    for key in data:
        log.error('%s: %s', key, data[key])

    return {}
