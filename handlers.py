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
import sys
import traceback
import base64
import os
import urllib
import hashlib

import webapp2
import webapp2_extras.json
import webapp2_extras.jinja2
import webapp2_extras.sessions
import webapp2_extras.auth
import webapp2_extras.i18n

from google.appengine.ext import ndb
from google.appengine.api import users
from google.appengine.api import namespace_manager
from google.appengine.ext import blobstore
from google.appengine.api import app_identity
from google.appengine.api import urlfetch
from google.appengine.api import memcache

from .utils import *
import oauth2
from .oauth2 import get_service

from .model_handler_mixin import ModelHandlerMixin

__all__ = ['BaseHandler',
           'ModelHandlerMixin',
           'NoKeyError',
           'UserIdentifierUsedError',
           'ConstantHandler',
           'tasklet',
           'Return',
           'BlobHandler',
           'ChunkedUploadHandler',
           'GeocodingHandler']

logger = logging.getLogger(__name__)
tasklet = ndb.tasklet
Return = ndb.Return

class Error(Exception):
  '''Error baseclass.'''


class NoKeyError(Error):
  '''No key to retrieve an entity.'''


class UserIdentifierUsedError(Error):
  '''Ocurrs when user creation fails.'''


class BaseHandler(webapp2.RequestHandler):
  '''
    Base handler. Allows sessions, template rendering, locale support,
    error rendering and basic auth support.
  '''
  # Whose users are allowed to access this resource
  # Empty array means all users: authorized and unauthorized
  # You can restrict by user type or user_id
  # TODO: We need dynamic users groups?
  users_allowed = []

  # Session backend used to mamnage sessions.
  session_backend = 'memcache'

  def __init__(self, *args, **kwargs):
    super(BaseHandler, self).__init__(*args, **kwargs)

    # Init auth store
    self.auth_store = webapp2_extras.auth.get_store(app=self.app)

    # Dict to store errors
    self.errors = {}

  def log_errors(self):
    '''Log errors'''
    url = self.request.route.build(self.request, self.request.route_args,
                                   self.request.route_kwargs)
    logger.error(u'Url:%s\nErrors: \n%s' % (url, self.errors))

  def render_errors(self, errors):
    '''
      Render handlers errors.
    '''
    self.errors.update(errors)
    self.log_errors()
    self.response.content_type = 'application/json'
    if not self.app.debug:
      for msg in self.errors['msgs']:
        del msg['traceback']
    return self.response.write(
      webapp2_extras.json.encode(self.errors, ensure_ascii=False,
                                 cls=JSONEncoder)
    )

  def render_json(self, jsonable, **kwargs):
    '''Render JSON response'''
    self.response.content_type = 'application/json'
    rv = self.encode_json(jsonable, **kwargs)

    # Allow JSONP requests
    if self.request.get('callback'):
      rv = self.request.get('callback') + '(' + rv + ')'
    return self.response.write(rv)

  def encode_json(self, jsonable, **kwargs):
    '''Encode in JSON format.'''
    return webapp2_extras.json.encode(jsonable, ensure_ascii=False,
                                      cls=JSONEncoder, **kwargs)

  def extract_json(self):
    '''Convert request body in JSON'''
    return self.decode_json(self.request.body)

  def decode_json(self, json_string, **kwargs):
    '''Decode from JSON format'''
    return webapp2_extras.json.decode(json_string)

  # Jinja2 support
  @webapp2.cached_property
  def jinja2(self):
    '''Returns a Jinja2 renderer cached in the app registry.'''
    return webapp2_extras.jinja2.get_jinja2(app=self.app)

  def get_logout_url(self, come_back_to='/'):
    '''
      Returns logout url.
      Assumes an attribute named 'come_back_to' where you can set redirection
      target url.
    '''
    try:
      logout_url = self.uri_for('logout') + '?come_back_to=%s' % come_back_to
    except KeyError:
      logout_url = users.create_logout_url(come_back_to)
    return logout_url

  def render_response(self, _template, **_context):
    '''Renders a template and writes the result to the response.'''
    version_config = self.app.config.load_config('lib_version')
    context = {
      'dev': self.app.debug,
      'user_json': self.encode_json(self.user),
      'user': self.user,
      'logout_url': self.get_logout_url(),
    }
    if (version_config):
      context.update(version_config)
    context.update(_context)
    rv = self.jinja2.render_template(_template, **context)
    self.response.write(rv)

  @webapp2.cached_property
  def user(self):
    '''Gets system user'''
    system_user = self.auth.get_user_by_session()
    user_model = self.auth.store.user_model
    if not system_user:
      appengine_user = users.get_current_user()

      if appengine_user:
        auth_id = appengine_user.email()
        system_user = user_model.get_by_auth_id(auth_id)
        if not system_user:
          auth_id = u'google:' + auth_id
          system_user = user_model.get_by_auth_id(auth_id)
    else:
      system_user = user_model.get_by_id(system_user['user_id'])

    return system_user

  def get_namespace(self):
      '''Gets namespace to store data.'''
      return self.request.host

  def set_namespace(self):
      '''Sets namespace for the request'''
      replace_map = [u':']
      namespace = self.get_namespace()
      for replace in replace_map:
          namespace = unicode(namespace).replace(replace, '.')
      self.namespace = namespace
      namespace_manager.set_namespace(self.namespace)

  def handle_exception(self, exception, debug):
    '''
      How you handle exceptions.
      We get error name, error message and formatted traceback and return
      them as JSON object.
    '''
    if getattr(exception, 'code', None):
      self.response.status = exception.code
    else:
      self.response.status = 500
    tb = sys.exc_info()[-1]
    ret = {
      'msgs': [{
        'msg': '%s: %s' % (exception.__class__.__name__, unicode(exception)),
        'level': 'error',
        'traceback': traceback.format_exc(tb),
      }]
    }
    return self.render_errors(ret)

  def get_login_url(self, come_back_to='/'):
    '''
      Returns login url.
      Defaults to appengine login url creation.
    '''
    try:
      login_url = self.uri_for('login') + '?come_back_to=%s' % come_back_to
    except KeyError:
      login_url = users.create_login_url(come_back_to)
    return login_url

  @ndb.toplevel
  def dispatch(self):
    # Set namespace
    self.set_namespace()

    # Get language to apply translations
    self.locale = self.request.headers.get('Accept-Language', 'es-ES')
    webapp2_extras.i18n.get_i18n().set_locale(self.locale)

    # Get a session store for this request.
    self.session_store = webapp2_extras.sessions.get_store(
      request=self.request
    )

    _dispatch = False
    if self.users_allowed:
      if self.user:
        if 'superhero' in self.user.type:
          _dispatch = True
        else:
          try:
            for type in self.user.type:
              _dispatch = _dispatch or type in self.users_allowed
              if _dispatch:
                break
            _dispatch = _dispatch or \
              self.user.get_id() in self.users_allowed
          except AttributeError:
            _dispatch = False
    else:
      _dispatch = True

    if _dispatch:
      try:
        super(BaseHandler, self).dispatch()
      except:
        raise
      finally:
        # Save all sessions.
        self.session_store.save_sessions(self.response)
    else:
      come_back_to = self.request.route.build(
        self.request,
        self.request.route_args,
        self.request.route_kwargs
      )
      redirect_to = self.get_login_url(come_back_to=come_back_to)
      self.redirect(redirect_to)

  @webapp2.cached_property
  def session(self):
      # Returns a session using the default cookie key.
      return self.session_store.get_session(backend=self.session_backend)

  @webapp2.cached_property
  def auth(self):
      return webapp2_extras.auth.get_auth(request=self.request)


class ConstantHandler(BaseHandler):
  '''
    Handler to serve contants values defined in code source.
    We assume the following structure to manage constants:
      CONSTANT = (
        (CONSTANT_VALUE, CONSTANT_LABEL),
      )
    So, the constant should be a sequence of two-element items where the first
    is the constant value and the second is a label to that value.
  '''
  constant = tuple()

  def get(self):
    '''Returns a JSON format of a constant defined in 'constant' attribute.'''
    self.render_json([{'label': c[1], 'value': c[0]} for c in self.constant if c[1]])


class BlobHandler(BaseHandler):
  '''Handler to serve a blob.
  The blob is served in base64 encoding; this encoding prevent browser cache.'''

  def get(self, blob_key=None):
    if not blob_key:
      return self.abort(401, 'No blob key provided.')

    try:
      blob = blobstore.BlobKey(blob_key)
      blob_info = blobstore.BlobInfo.get(blob)
      if not blob_info:
        raise Exception
    except:
      return self.abort(404, 'No model found.')

    reader = blobstore.BlobReader(blob)
    self.response.headers.add('Content-Tranfer-Encoding', 'base64')
    self.response.content_type = str(blob_info.content_type)
    self.response.write('data:%s;base64,' % blob_info.content_type)
    self.response.write(base64.b64encode(reader.read()))


class ChunkedUploadHandler(BaseHandler):
  '''Handles chunked uploads.
  With this handler you can implement a resumable upload.'''

  acl = 'public-read'

  @webapp2.cached_property
  def _local(self):
    server_software = os.environ.get('SERVER_SOFTWARE')
    if server_software is None:
      return True
    if 'remote_api' in server_software:
      return False
    if server_software.startswith(('Development', 'testutil')):
      return True
    return False

  @webapp2.cached_property
  def base_path(self):
    '''Gets base path to make requests against Google Cloud Storage.'''
    if self._local:
      return self.request.host_url + '/_ah/gcs'
    else:
      return 'https://www.googleapis.com'

  def get_access_token(self):
    '''Get OAuth2 access token to sign requests.'''
    scopes = [
      'https://www.googleapis.com/auth/devstorage.read_write',
      'https://www.googleapis.com/auth/devstorage.full_control',
      'https://www.googleapis.com/auth/devstorage.read_only',
    ]
    return app_identity.get_access_token(scopes)

  def get_range(self):
    '''Extract range information.'''
    range1, total_size = self.request.headers['Content-Range'].split('/')
    range1 = range1[6:]
    start, stop = range1.split('-')
    return int(start), int(stop), int(total_size)

  @webapp2.cached_property
  def bucket_name(self):
    return os.environ.get('GCS_BUCKET_NAME',
                          app_identity.get_default_gcs_bucket_name())

  def post(self):
    start, stop, total_size = self.get_range()
    assert start == 0
    last = stop == total_size - 1

    filename = self.request.get('filename', get_random_string(18))

    access_token, _ = self.get_access_token()
    if self._local:
      init_url = '%s/%s/o?uploadType=resumable&name=%s' % (
        self.base_path, self.bucket_name, filename)
    else:
      init_url = '%s/upload/storage/v1/b/%s/o?uploadType=resumable&name=%s' % (
        self.base_path, self.bucket_name, filename)
    init_headers = {
      'Authorization': 'Bearer %s' % access_token,
      'x-goog-acl': self.acl
    }
    init = urlfetch.fetch(url=init_url, headers=init_headers,
                          method=urlfetch.POST)
    if init.status_code >= 200 and init.status_code < 300:
      session = init.headers['Location']
      mem_key = '%s|%s' % ('GCS-Sessions', filename)
      memcache.add(key=mem_key, value=session)

      upload_headers = {
        'Authorization': 'Bearer %s' % access_token,
        'Content-Type': self.request.content_type,
        'Content-Range': 'bytes %s-%s/*' % (start, stop),
      }
      if last:
        upload_headers['Content-Range'] = 'bytes %s-%s/%s' % (
          start, stop, total_size)
      upload_content = fix_base64_padding(self.request.body)
      upload_content = base64.b64decode(upload_content)
      logger.info('Fetching %s' % session)
      upload = urlfetch.fetch(url=session, method=urlfetch.PUT,
                              payload=upload_content, headers=upload_headers)
      if upload.status_code == 308:
        logger.info('308 Redirection...')
        self.render_json({
          'filename': filename,
          'start': start,
          'stop': stop,
          'lenght': len(upload_content),
        })
        self.response.status = 201
      elif upload.status_code == 200:
        logger.info('200 Last chunk...')
        if not last:
          # ??? no debería
          logger.debug('Mmmm... This is suspicious and should not be happening...')

        if self._local:
          medialink_url = '%s/%s/%s' % (self.base_path, self.bucket_name,
                                        filename)
        else:
          medialink_url = '%s/storage/v1/b/%s/o/%s' % (self.base_path,
                                                      self.bucket_name,
                                                      filename)
        medialink = urlfetch.fetch(method=urlfetch.GET, url=medialink_url,
          headers={
            'Authorization': 'Bearer %s' % access_token,
          })
        if medialink.status_code >= 200 and medialink.status_code < 300:
          medialink = self.decode_json(medialink.content)['mediaLink']
        else:
          medialink = None

        self.render_json({
          'filename': filename,
          'start': start,
          'stop': stop,
          'lenght': len(upload_content),
          'url': medialink,
        })
        self.response.status = 200
        memcache.delete(mem_key)
      else:
        logger.error('An error has ocurred while trying to upload. Try again.')
        logger.error('Upload URL: %s' % session)
        logger.error('Status code %s: %s' % (upload.status_code, upload.content))
        return self.abort(500, 'An error has ocurred while trying to upload. Try again.')
    else:
      logger.error('Impossible to create a new file in Google Cloud Storage.')
      logger.info('Creation URL: %s' % init_url)
      logger.error('Status code %s: %s' % (init.status_code, init.content))
      return self.abort(507,
        'Impossible to create a new file in Google Cloud Storage.')

  def put(self):
    start, stop, total_size = self.get_range()
    last = stop == total_size - 1

    filename = self.request.get('filename')
    if not filename:
      return self.abort(412, 'Filename is mandatory.')

    mem_key = '%s|%s' % ('GCS-Sessions', filename)
    session = memcache.get(mem_key)
    if not session:
      return self.abort(404, 'Upload session not found.')

    access_token, _ = self.get_access_token()
    upload_headers = {
      'Authorization': 'Bearer %s' % access_token,
      'Content-Type': self.request.content_type,
      'Content-Range': 'bytes %s-%s/*' % (start, stop),
    }
    if last:
      upload_headers['Content-Range'] = 'bytes %s-%s/%s' % (
        start, stop, total_size)
    upload_content = fix_base64_padding(self.request.body)
    upload_content = base64.b64decode(upload_content)
    logger.info('Fetching %s' % session)
    upload = urlfetch.fetch(url=session, method=urlfetch.PUT,
                            payload=upload_content, headers=upload_headers)
    if upload.status_code == 308:
      logger.info('308 Redirection...')
      self.render_json({
        'filename': filename,
        'start': start,
        'stop': stop,
        'lenght': len(upload_content),
      })
      self.response.status = 201
    elif upload.status_code == 200:
      logger.info('200 Last chunk...')
      if not last:
        # ??? no debería
        logger.debug('Mmmm... This is suspicious and should not be happening...')

      if self._local:
        medialink_url = '%s/%s/%s' % (self.base_path, self.bucket_name,
                                      filename)
      else:
        medialink_url = '%s/storage/v1/b/%s/o/%s' % (self.base_path,
                                                    self.bucket_name,
                                                    filename)
      medialink = urlfetch.fetch(method=urlfetch.GET, url=medialink_url,
        headers={
          'Authorization': 'Bearer %s' % access_token,
        })
      if medialink.status_code >= 200 and medialink.status_code < 300:
        medialink = self.decode_json(medialink.content)['mediaLink']
      else:
        medialink = None

      self.render_json({
        'filename': filename,
        'start': start,
        'stop': stop,
        'lenght': len(upload_content),
        'url': medialink,
      })
      self.response.status = 200
      memcache.delete(mem_key)
    else:
      logger.error('An error has ocurred while trying to upload. Try again.')
      logger.error('Status code %s: %s' % (upload.status_code, upload.content))
      logger.info('Upload length: %s' % len(upload_content))
      logger.info('Upload range: %s' % (stop - start))
      logger.info('Upload 256kb multiple?: %s' % ((len(upload_content) % (256 * 1024)) == 0))
      return self.abort(500, 'An error has ocurred while trying to upload. Try again.')


class GeocodingHandler(BaseHandler):
  '''Handler to manage geocoding requests.

  We use Google Maps to perform geocoding. Also we use memcache to cache Google
  maps responses.'''

  def get_memcache_key(self, **kwargs):
    '''Calculate memcache key.'''
    h = hashlib.md5()
    for key, value in kwargs.iteritems():
      h.update(value)
    return h.hexdigest()

  def get(self):
    search_term = self.request.get('q')
    if not search_term:
      return self.abort(404)

    if len(search_term) < 3:
      return self.abort(412, 'Search term is too short.')

    google_maps_key = self.app.config.load_config('GOOGLE_APIS')
    if google_maps_key:
      google_maps_key = google_maps_key.get('key', None)
    else:
      google_maps_key = None

    components = self.request.get('c', '')
    region = self.request.get('r', '')
    language = 'es'  # TODO: detect language from headers

    params = {
      'sensor': 'false',
      'address': search_term.encode('utf-8'),
    }
    if components:
      params['components'] = components
    if region:
      params['region'] = region
    # if google_maps_key:
    #   params['key'] = google_maps_key
    if language:
      params['language'] = language

    cached = memcache.get(
      'GOOGLE_MAPS_GEOCODING|%s' % self.get_memcache_key(**params))
    if cached:
      return self.render_json(cached)
    else:
      url = 'http://maps.googleapis.com/maps/api/geocode/json?%s'
      url = url % urllib.urlencode(params)
      req = urlfetch.fetch(url)
      logger.info('Fetching from Google Maps...')

      if req.status_code == 200:
        result = self.decode_json(req.content)

        if result['status'] == 'OK':
          memcache.add(
            'GOOGLE_MAPS_GEOCODING|%s' % self.get_memcache_key(**params),
            result['results'],
            60 * 60 * 24 * 7)  # keep it for 7 days
          return self.render_json(result['results'])
        elif result['status'] == 'ZERO_RESULTS':
          return self.render_json([])
        else:
          logger.warning('Impossible to retrieve geocodes.')
          logger.warning('Response code: %s' % result['status'])
          return self.abort(500)
      else:
        logger.warning('Impossible to retrieve geocodes.')
        logger.warning('Status code: %s' % req.status_code)
        logger.warning('Reason: %s' % req.content)
        return self.abort(500)
