#!/usr/bin/env python
#-*- coding: utf-8 -*-

# This file is part of Stones Server Side.

# Stones Server Side is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Stones Server Side is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Stones Server Side.  If not, see <http://www.gnu.org/licenses/>.

# Copyright 2013, Carlos León <carlos.eduardo.leon.franco@gmail.com>


import logging
import httplib2
import urllib
import urlparse
import random
import string

logger = logging.getLogger(__name__)

try:
  from urlparse import parse_qs, parse_qsl
except ImportError:
  from cgi import parse_qs, parse_qsl

try:
  import simplejson as json
except ImportError:
  import json

__all__ = ['OAuth2Service', 'OAuth2ServicesError', 'OAuth2ClientError',
           'OAuth2Client', 'OAuth2Token', 'OAuth2Error', 'get_service']


class OAuth2Error(Exception):
  pass


class OAuth2ClientError(OAuth2Error):
  pass


class OAuth2ServicesError(OAuth2Error):
  pass


class OAuth2Client(object):
  """Client for OAuth 2.0 draft spec
  https://svn.tools.ietf.org/html/draft-hammer-oauth2-00
  Extracted from:
  https://github.com/dgouldin/python-oauth2/blob/master/oauth2/__init__.py
  """

  def __init__(self, client_id, client_secret, request_token_uri,
               access_token_uri, redirect_uri):
    '''Constructor.'''
    self.client_id = client_id
    self.client_secret = client_secret
    self.redirect_uri = redirect_uri
    self.request_token_uri = request_token_uri
    self.access_token_uri = access_token_uri

    ok = self.client_id and self.client_secret and self.request_token_uri \
      and self.access_token_uri
    if not ok:
      raise ValueError("client_id, client_secret, request_token_uri and "
                       "access_token_uri must be set.")

    self.http = httplib2.Http()

  @staticmethod
  def _split_url_string(param_str):
    """Turn URL string into parameters."""
    parameters = parse_qs(param_str, keep_blank_values=False)
    for key, val in parameters.iteritems():
      parameters[key] = urllib.unquote(val[0])
    return parameters

  @staticmethod
  def get_data_from_response(response_body):
    try:
      return json.loads(response_body)
    except Exception, e:
      return OAuth2Client._split_url_string(response_body)

  def authorization_url(self, **kwargs):
    """Get the URL to redirect the user for client authorization
    https://svn.tools.ietf.org/html/draft-hammer-oauth2-00#section-3.5.2.1
    """

    # prepare required args
    args = {
      'client_id': self.client_id,
    }

    # prepare optional args
    redirect_uri = kwargs.pop('redirect_uri', False) or self.redirect_uri
    if redirect_uri is not None:
      args['redirect_uri'] = redirect_uri

    for key, value in kwargs.iteritems():
      args[key] = value

    return '%s?%s' % (self.request_token_uri, urllib.urlencode(args))

  def access_token(self, code, **kwargs):
    """Get an access token from the supplied code
    https://svn.tools.ietf.org/html/draft-hammer-oauth2-00#section-3.5.2.2
    """

    # prepare required args
    if code is None:
      raise ValueError("Code must be set.")
    args = {
      'client_id': self.client_id,
      'client_secret': self.client_secret,
      'code': code,
    }

    for key, value in kwargs.iteritems():
      args[key] = value

    uri = self.access_token_uri
    body = urllib.urlencode(args)
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    response, content = self.http.request(uri, method='POST', body=body,
                                          headers=headers)
    if not response.status == 200:
      raise OAuth2ClientError(content)
    response_args = OAuth2Client.get_data_from_response(content)

    error = response_args.pop('error', None)
    if error is not None:
      raise OAuth2Error(error)

    refresh_token = response_args.pop('refresh_token', None)
    if refresh_token is not None:
      response_args = self.refresh(refresh_token, secret_type=secret_type)
    return response_args

  def refresh(self, refresh_token, **kwargs):
    """Get a new access token from the supplied refresh token
    https://svn.tools.ietf.org/html/draft-hammer-oauth2-00#section-4
    """

    if refresh_token is None:
      raise ValueError("Refresh_token must be set.")

    # prepare required args
    args = {
      'client_id': self.client_id,
      'client_secret': self.client_secret,
      'refresh_token': refresh_token,
    }

    for key, value in kwargs.iteritems():
      args[key] = value

    uri = self.access_token_uri
    body = urllib.urlencode(args)
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    response, content = self.http.request(uri, method='POST', body=body,
                                          headers=headers)
    if not response.status == 200:
      raise Oauth2ClientError(content)

    response_args = OAuth2Client.get_data_from_response(content)
    return response_args

  def request(self, base_uri, access_token=None, method='GET', body=None,
              headers=None, params=None, token_param='oauth_token'):
    """Make a request to the OAuth API"""

    args = {}
    args.update(params or {})
    if access_token is not None and method == 'GET':
      args[token_param] = access_token
    uri = '%s?%s' % (base_uri, urllib.urlencode(args))
    return self.http.request(uri, method=method, body=body, headers=headers)


class OAuth2Token(object):
  '''Token representation to hold oauth flow data'''
  access_token = ''
  refresh_token = ''
  expires_in = ''
  token_type = ''

  def __init__(self, access_token=None, refresh_token=None, expires_in=None,
               token_type='Bearer', **kwargs):
    self.access_token = access_token
    self.refresh_token = refresh_token
    self.expires_in = expires_in
    self.token_type = token_type

    for attr, value in kwargs.iteritems():
      setattr(self, attr, value)


class OAuth2Service(object):
  '''Represents one OAuth2 service provider'''
  client_id = ''
  client_secret = ''
  request_token_uri = ''
  access_token_uri = ''
  redirect_uri = ''
  scope = []
  display = ''

  def __init__(self, client_id, client_secret, request_token_uri,
               access_token_uri, redirect_uri, scope, display=''):
    self.client_id = client_id
    self.client_secret = client_secret
    self.request_token_uri = request_token_uri
    self.access_token_uri = access_token_uri
    self.redirect_uri = redirect_uri
    self.display = display

    if isinstance(scope, basestring):
      self.scope = scope.split(' ')
    else:
      self.scope = scope

    self.client = OAuth2Client(
      client_id=self.client_id,
      client_secret=self.client_secret,
      request_token_uri=self.request_token_uri,
      access_token_uri=self.access_token_uri,
      redirect_uri=self.redirect_uri
    )
    self.token = OAuth2Token()

  def get_authorization_url(self, **kwargs):
    if not 'client_id' in kwargs:
      kwargs['client_id'] = self.client_id
    if not 'response_type' in kwargs:
      kwargs['response_type'] = 'code'
    if not 'scope' in kwargs:
      kwargs['scope'] = ' '.join(self.scope)
    if not 'state' in kwargs:
      kwargs['state'] = ''.join(
        random.sample(string.ascii_letters + string.digits, 32))

    come_back_to = kwargs.pop('come_back_to', None)
    if come_back_to:
      kwargs['state'] += '|%s' % come_back_to
    return self.client.authorization_url(**kwargs)

  def get_access_token(self, code, **kwargs):
    if kwargs.get('grant_type', None) is None:
      kwargs['grant_type'] = 'authorization_code'
    if kwargs.get('redirect_uri', None) is None:
      kwargs['redirect_uri'] = self.redirect_uri
    new_token = self.client.access_token(code, **kwargs)
    self.token = OAuth2Token(**new_token)
    return self.token

  def refresh_access_token(self, **kwargs):
      new_token = self.client.refresh(self.token.refresh_token, **kwargs)
      self.token = OAuth2Token(**new_token)
      return self.token

  def make_request(self, base_uri, method='GET', headers=None, params=None,
                   body=None, token_param='access_token'):
    _headers = {
      'Authorization': ' '.join([self.token.token_type,
                                 self.token.access_token])
    }
    if headers:
      _headers.update(headers)

    return self.client.request(base_uri, self.token.access_token, method,
                               body, _headers, params, token_param)

  def get_user_info(self, token=None):
    '''Returns a dictionary filled with user info'''
    raise NotImplemented()


class GoogleOAuth2Service(OAuth2Service):
  '''Google OAuth2 specific service'''
  def __init__(self, client_id, client_secret, redirect_uri, **kwargs):
    defaults = {
      'client_id': client_id,
      'client_secret': client_secret,
      'redirect_uri': redirect_uri,
      'request_token_uri': 'https://accounts.google.com/o/oauth2/auth',
      'access_token_uri': 'https://accounts.google.com/o/oauth2/token',
    }
    defaults.update(kwargs)
    super(GoogleOAuth2Service, self).__init__(**defaults)

  def get_user_info(self, token=None):
    if token is None:
      token = self.token
    else:
      self.token = token

    base_uri = 'https://www.googleapis.com/oauth2/v1/userinfo'
    response, content = self.make_request(base_uri)

    if not response.status == 200:
      raise OAuth2ServicesError(content)
    person = OAuth2Client.get_data_from_response(content)
    # TODO: Modify persons keys (extracted from LinkedInOAuth2Service)
    rv = {
      'email': person['emailAddress'],
      'first_name': person['firstName'],
      'last_name': person['lastName'],
      'job': person['headline'],
      'picture_url': person['pictureUrl'],
      'profile_url': person['publicProfileUrl'],
    }
    return rv


class FacebookOAuth2Service(OAuth2Service):
  '''Facebook OAuth2 specific service'''
  def get_user_info(self, token=None):
    if token is None:
      token = self.token
    else:
      self.token = token

    base_uri = 'https://graph.facebook.com/me'
    response, content = self.make_request(base_uri)

    if not response.status == 200:
        raise OAuth2ServicesError(content)
    person = OAuth2Client.get_data_from_response(content)

    return person


class LinkedInOAuth2Service(OAuth2Service):
  '''LinkedIn OAuth2 specific service'''
  def __init__(self, client_id, client_secret, redirect_uri, **kwargs):
    defaults = {
      'client_id': client_id,
      'client_secret': client_secret,
      'redirect_uri': redirect_uri,
      'request_token_uri': 'https://www.linkedin.com/uas/oauth2/authorization',
      'access_token_uri': 'https://www.linkedin.com/uas/oauth2/accessToken',
    }
    defaults.update(kwargs)
    super(LinkedInOAuth2Service, self).__init__(**defaults)

  def make_request(self, base_uri, method='GET', headers=None, params=None,
                   body=None, token_param='access_token'):
    _headers = {}
    if headers:
      _headers.update(headers)
    return self.client.request(base_uri, self.token.access_token, method,
                               body, _headers, params, token_param)


  def get_user_info(self, token=None):
    if token is None:
      token = self.token
    else:
      self.token = token

    base_uri = 'https://api.linkedin.com/v1/people/'
    params = {'format': 'json'}
    response, content = self.make_request(
      base_uri + '~:(email-address,first-name,last-name,headline,picture-url,public-profile-url)',
      token_param='oauth2_access_token',
      params=params)

    if not response.status == 200:
        raise OAuth2ServicesError(content)
    person = json.loads(content)
    rv = {
      'email': person['emailAddress'],
      'first_name': person['firstName'],
      'last_name': person['lastName'],
      'job': person['headline'],
      'picture_url': person['pictureUrl'],
      'profile_url': person['publicProfileUrl'],
    }
    return rv


def get_service(service_name):
  '''Returns proper service class linked with service_name'''
  if service_name == 'google':
    return GoogleOAuth2Service
  elif service_name == 'facebook':
    return FacebookOAuth2Service
  elif service_name == 'linkedin':
    return LinkedInOAuth2Service
  else:
    raise OAuth2ServicesError('No %s service supported.' % service_name)
