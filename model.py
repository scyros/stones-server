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

import os
import datetime
import logging
import re
import base64
import random
import string
import calendar
import time

from google.appengine.ext import ndb
from google.appengine.ext.ndb.model import _StructuredGetForDictMixin as ndb_StructuredGetForDictMixin
from google.appengine.ext.ndb.google_imports import datastore_errors
from google.appengine.api.users import User
from google.appengine.ext import blobstore
from google.appengine.api import app_identity
from google.appengine.api import urlfetch

import utils

logger = logging.getLogger(__name__)

DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DATE_FORMAT = '%Y-%m-%d'
TIME_FORMAT = '%H:%M:%S'

BASE64_HEADER_REGEX = re.compile("data:(\w*)/(.+);base64")
URL_REGEX = re.compile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
LOCAL_URL_REGEX = re.compile("/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")


def check_list(value):
  if not isinstance(value, (list, tuple, set, frozenset)):
    raise datastore_errors.BadValueError('Expected list or tuple,'
                                         ' got %r' % (value,))


class _SetFromDictPropertyMixin(object):
  '''Mixin to add "from_dict" functionality.'''
  def _set_from_dict(self, value):
    '''Returns a proper value to property but not sets it.'''
    if self._repeated:
      check_list(value)
      return [self._do_validate(v) for v in value]
    return self._do_validate(value)


class GenericProperty(_SetFromDictPropertyMixin, ndb.GenericProperty):
  '''GenericProperty modified.'''


class StringProperty(_SetFromDictPropertyMixin, ndb.StringProperty):
  '''StringProperty modified.'''


class IntegerProperty(_SetFromDictPropertyMixin, ndb.IntegerProperty):
  ''''IntegerProperty modified.'''
  def _set_from_dict(self, value):
    '''Returns a proper value to property but not sets it.'''
    if self._repeated:
      check_list(value)
      value = [int(val) for val in value]
      return [self._do_validate(v) for v in value]
    return self._do_validate(int(value))


class FloatProperty(_SetFromDictPropertyMixin, ndb.FloatProperty):
  '''FloatProperty modified.'''
  def _set_from_dict(self, value):
    '''Returns a proper value to property but not sets it.'''
    if self._repeated:
      check_list(value)
      value = [float(val) for val in value]
      return [self._do_validate(v) for v in value]
    return self._do_validate(float(value))


class BooleanProperty(_SetFromDictPropertyMixin, ndb.BooleanProperty):
  '''BooleanProperty modified.'''
  def _set_from_dict(self, value):
    '''Returns a proper value to property but not sets it.'''
    def cast(val):
      if val in ['false', 'False']:
        return False
      return bool(val)

    if self._repeated:
      check_list(value)
      value = [cast(val) for val in value]
      return [self._do_validate(v) for v in value]
    return self._do_validate(cast(value))


class TextProperty(_SetFromDictPropertyMixin, ndb.TextProperty):
    '''TextProperty modified.'''


class BlobProperty(_SetFromDictPropertyMixin, ndb.BlobProperty):
  '''BlobProperty modified.'''
  def _set_from_dict(self, value):
    def cast(val):
      return str(val)

    if self._repeated:
      return [self._do_validate(cast(v)) for v in value]
    return self._do_validate(cast(value))


class JsonProperty(_SetFromDictPropertyMixin, ndb.JsonProperty):
  '''JsonProperty modified.'''


class DateProperty(_SetFromDictPropertyMixin, ndb.DateProperty):
  '''DateProperty modified.'''
  def _set_from_dict(self, value):
    def cast(val):
      if isinstance(val, basestring):
        val = datetime.datetime.strptime(val, DATE_FORMAT)
        val = val.date()
      return val

      if self._repeated:
        return [self._do_validate(cast(value)) for v in value]
    return self._do_validate(cast(value))


class DateTimeProperty(_SetFromDictPropertyMixin, ndb.DateTimeProperty):
  ''''DateTimeProperty modified.'''
  def _set_from_dict(self, value):
    if isinstance(value, basestring):
      value = datetime.datetime.strptime(value, DATETIME_FORMAT)
    return self._do_validate(value)


class TimeProperty(_SetFromDictPropertyMixin, ndb.TimeProperty):
  '''TimeProperty modified.'''
  def _set_from_dict(self, value):
    def cast(val):
      if isinstance(val, basestring):
        val = datetime.datetime.strptime(val, TIME_FORMAT)
        val = val.time()
      return val

    if self._repeated:
      return [self._do_validate(cast(v)) for v in value]
    return self._do_validate(cast(value))


class KeyProperty(_SetFromDictPropertyMixin, ndb.KeyProperty):
  '''KeyProperty modified.'''
  def _set_from_dict(self, value):
    def cast(val):
      if isinstance(val, basestring):
        val = ndb.Key(urlsafe=val)
      elif isinstance(val, dict):
        if val.get('urlsafe_key', None):
          val = ndb.Key(urlsafe=val['urlsafe_key'])
        elif val.get('__key__', None):
          val = ndb.Key(urlsafe=val['__key__'])
      return val

    if self._repeated:
      return [self._do_validate(cast(v)) for v in value]
    return self._do_validate(cast(value))


class BlobKeyProperty(_SetFromDictPropertyMixin, ndb.BlobKeyProperty):
  '''BlobKeyProperty modifies.'''
  def _set_from_dict(self, value):
    def cast(val):
      if isinstance(val, basestring):
        return blobstore.BlobKey(val)
      else:
        raise datastore_errors.BadValueError('Expected string, got %r.' % val)

    if self._repeated:
      return [self._do_validate(cast(v)) for v in value]
    return self._do_validate(cast(value))


class GCSBlobProperty(StringProperty):
  '''Property to store access URL to a Google Cloud Storage object.'''
  def __init__(self, name, acl=None, *args, **kwargs):
    super(GCSBlobProperty, self).__init__(name, *args, **kwargs)
    self.acl = acl
    if self.acl:
      options = ('private', 'public-read', 'public-read-write',
                 'authenticated-read', 'bucket-owner-read',
                 'bucket-owner-full-control')
      assert self.acl in options, 'Invalid ACL "%s"' % self.acl

  def get_access_token(self):
    '''Get OAuth2 access token to sign requests.'''
    scopes = [
      'https://www.googleapis.com/auth/devstorage.read_write',
      'https://www.googleapis.com/auth/devstorage.full_control',
      'https://www.googleapis.com/auth/devstorage.read_only',
    ]
    return app_identity.get_access_token(scopes)

  @property
  def _local(self):
    server_software = os.environ.get('SERVER_SOFTWARE')
    if server_software is None:
      return True
    if 'remote_api' in server_software:
      return False
    if server_software.startswith(('Development', 'testutil')):
      return True
    return False

  @property
  def base_path(self):
    '''Gets base path to make requests against Google Cloud Storage.'''
    if self._local:
      return '/_ah/gcs'
    else:
      return 'https://www.googleapis.com/storage/v1/b'

  def is_base64(self, value):
    try:
      header = value.split(',')[0]
      return bool(BASE64_HEADER_REGEX.search(header))
    except:
      return False

  def get_base64_content(self, value):
    header, content = value.split(',')
    return content

  def get_base64_mimetype(self, value):
    header = value.split(',')[0]
    r = BASE64_HEADER_REGEX.search(header)
    return '/'.join(r.groups())

  def _set_from_dict(self, value):
    def cast(val):
      if isinstance(val, basestring):
        if self.is_base64(val):
          mimetype = self.get_base64_mimetype(val)
          base64_string = self.get_base64_content(val)
          base64_decoded = base64.b64decode(base64_string)
          base64_string = None
          bucket = os.environ.get('GCS_BUCKET_NAME',
            app_identity.get_default_gcs_bucket_name())
          filename = utils.get_random_string(12)
          filename += str(calendar.timegm(time.gmtime()))

          import cloudstorage as gcs

          acl = None
          if self.acl:
            acl = {'x-goog-acl': self.acl}
          with gcs.open('/%s/%s' % (bucket, filename), 'w',
                        content_type=mimetype, options=acl) as gcs_file:
            gcs_file.write(base64_decoded)

          if self._local:
            return '%s/%s/%s' % (self.base_path, bucket, filename)
          access_token, _ = self.get_access_token()
          medialink_url = '%s/%s/o/%s' % (self.base_path, bucket, filename)
          medialink = urlfetch.fetch(
            method=urlfetch.GET,
            url=medialink_url,
            headers={
              'Authorization': 'Bearer %s' % access_token,
            })
          if medialink.status_code >= 200 and medialink.status_code < 300:
            return utils.decode_json(medialink.content)['mediaLink']
          return None
        elif URL_REGEX.findall(val):
          return val
        elif LOCAL_URL_REGEX.findall(val):
          return val
        else:
          raise datastore_errors.BadValueError('Expected Base64 string or '
                                               'URL, got %r.' % val)
      else:
        raise datastore_errors.BadValueError('Expected string, got %r.' % val)

    if self._repeated:
      return [self._do_validate(cast(v)) for v in value]
    return self._do_validate(cast(value))


class UserProperty(_SetFromDictPropertyMixin, ndb.UserProperty):
  '''UserProperty modified.'''
  def _set_from_dict(self, value):
    def cast(val):
      if isinstance(val, basestring):
        val = User(val)
      elif isinstance(val, dict):
        val = User(val['email'])
      return val

    if self._repeated:
      return [self._do_validate(cast(v)) for v in value]
    return self._do_validate(cast(value))


class ComputedProperty(_SetFromDictPropertyMixin, ndb.ComputedProperty):
  '''ComputedProperty modified.'''
  def _set_from_dict(self, value):
    return None


class GeoPtProperty(_SetFromDictPropertyMixin, ndb.GeoPtProperty):
  '''GeoPtProperty modified.'''
  def _set_from_dict(self, value):
    def cast(val):
      if isinstance(val, (list, tuple, frozenset)):
        val = (val[0], val[1])
      elif isinstance(val, dict):
        val = (val['lat'], val.get('lng', None) or val.get('lon', None))
      return ndb.GeoPt(*val)

    if self._repeated:
      return [self._do_validate(cast(v)) for v in value]
    return self._do_validate(cast(value))


class _StructuredSetFromDictMixin(object):
  '''Mixin to add "from_dict" functionality.'''
  def _set_from_dict(self, value):
    if self._repeated:
      check_list(value)
      _value = []
      for v in value:
        _value.append(self._modelclass.from_dict(v))
      return _value
    elif value is None:
      return None
    else:
      if not isinstance(value, dict):
        raise datastore_errors.BadValueError('Expected dict, got %r.'
                                             % (value,))
      return self._modelclass.from_dict(value)


class StructuredProperty(_StructuredSetFromDictMixin, ndb.StructuredProperty):
  '''StructuredProperty modified.'''


class LocalStructuredProperty(ndb.LocalStructuredProperty,
                              _StructuredSetFromDictMixin):
  '''LocalStructuredProperty modified.'''


def get_prop(prop_name, properties):
  '''Gets a property instance from its formal name (code_name).'''
  assert isinstance(properties, dict), 'Properties should be a dict.'
  for prop in properties.itervalues():
    if prop._code_name == prop_name:
      return prop
  logger.warning('%s attribute not found.' % prop_name)


class Model(ndb.Model):
  '''New Model "from_dict" capable.'''
  def __unicode__(self):
    if hasattr(self, 'display'):
      if self.display is None:
        return u''
      return self.display
    else:
      return super(Model, self).__unicode__()

  @classmethod
  def _initial_values_from_dict(cls, value):
    '''Extract model attribute values from dict.'''
    if not isinstance(value, dict):
      raise datastore_errors.BadValueError('Expected dict, got %r.'
                                           % (value,))

    props_names = value.keys()
    parent = None
    if 'parent' in props_names:
      parent = ndb.Key(urlsafe=value['parent'])
    initial_values = {
      'parent': parent,
    }
    for prop in cls._properties.itervalues():
      name = prop._code_name
      if name in props_names and not isinstance(prop, ndb.ComputedProperty):
        _value = value[name]
        if not _value is None:
          has_set_from_dict = hasattr(prop, '_set_from_dict')
          if not has_set_from_dict is None:
            initial_values[name] = prop._set_from_dict(_value)
    return initial_values

  @classmethod
  def _from_dict(cls, value):
    '''Creates a new entity from data cointained in a dict, for example, a
    JSON structure.

    Args:
        value: dict with entity data.'''
    initial_values = cls._initial_values_from_dict(value)
    return cls(**initial_values)
  from_dict = _from_dict

  def _populate_from_dict(self, json):
    '''Populates the entity with data from dict.'''
    values = self._initial_values_from_dict(json)
    parent = values.pop('parent', None)
    for key, value in values.iteritems():
      prop = get_prop(key, self._properties)
      prop._set_value(self, value)

  def _pre_put_hook(self):
    '''Determines if any inner ReferenceProperty must be saved after save
    the entity.'''
    self._unsaved_references = []
    for unused, prop in self._properties.iteritems():
      if isinstance(prop, ReferenceProperty):
        prop_value = prop._get_value(self)
        if prop._repeated:
          for v_index, value in enumerate(prop_value):
            if not value is None:
              if not value.urlsafe_key and prop._original[v_index]:
                self._unsaved_references.append(prop)
                break
        else:
          value = prop_value
          if not value is None:
            urlsafe_key = value.urlsafe_key
            if not urlsafe_key and prop._original:
              # we need to save it after save the entity.
              self._unsaved_references.append(prop)

  def _post_put_hook(self, future):
    '''Saves the unsaved references.'''
    if not self._unsaved_references:
      return

    self._save_again = False
    self_key = future.get_result()
    saved_originals = []
    for prop in self._unsaved_references:
      prop_value = prop._get_value(self)
      prop_original = prop._original
      if prop._repeated:
        inner_originals = []  # to hold original entity from each value
        for v_index, value in enumerate(prop_value):
          if not value.urlsafe_key:
            if prop._allow_new:
              original_args = prop_original[v_index]._to_dict()
              if prop._is_child:
                new_value = prop._original_class(parent=self_key,
                                                 **original_args)
              else:
                new_value = prop._original_class(**original_args)
              inner_originals.append(new_value.put_async())
            else:
              inner_originals.append(None)
          else:
            inner_originals.append(value.urlsafe_key)
        saved_originals.append(inner_originals)
      else:
        value = prop_value
        if not value.urlsafe_key:
          if prop._allow_new:
            original_args = prop._original._to_dict()
            if prop._is_child:
              prop._original = prop._original_class(parent=self_key,
                                                    **original_args)
            else:
              prop._original = prop._original_class(**original_args)
            saved_originals.append(prop._original.put_async())

    for index, reference_future in enumerate(saved_originals):
      # we are going to manipulate the first property always until
      # saved_originals will be empty
      prop = self._unsaved_references.pop(0)  # pop the 1st item always
      prop_value = prop._get_value(self)
      if prop._repeated:
        prop_value_shadow = []
        for v_index, value in enumerate(prop_value):
          ref_future = reference_future[v_index]
          if isinstance(ref_future, basestring):
            ref_key = ref_future
          elif not getattr(ref_future, 'get_result', None) is None:
            ref_key = ref_future.get_result().urlsafe()
          else:
            ref_key = None

          if not ref_key is None:
            value.urlsafe_key = ref_key
            prop_value_shadow.append(value)
          self._save_again = True
        prop._set_value(self, prop_value_shadow)
      else:
        ref_key = reference_future.get_result()
        prop_value.urlsafe_key = ref_key.urlsafe()
        self._save_again = True

      if self._save_again:
        self.put_async()

  def to_dict(self):
    '''Returns a dict with special keys __key__ and __id__ added to
    entity values dict.'''
    _to_dict = super(Model, self).to_dict()
    if self._has_complete_key():
      _to_dict['__id__'] = self.key.id()
      _to_dict['__key__'] = self.key.urlsafe()
    return _to_dict


class Expando(ndb.Expando, Model):
  '''Stones Expando version. Adds to Expando the new functionality.'''
  def __setattr__(self, name, value):
    '''Extracted from google.appengine.ext.ndb.model:3496 v:1.8.3.
    Overrided to fix properties references.'''
    if (name.startswith('_') or
        isinstance(getattr(self.__class__, name, None),
                   (ndb.Property, property))):
      return super(Expando, self).__setattr__(name, value)
    # TODO: Refactor this to share code with _fake_property().
    self._clone_properties()
    if isinstance(value, Model):
      prop = StructuredProperty(Model, name)
    elif isinstance(value, dict):
      prop = StructuredProperty(Expando, name)
    else:
      repeated = isinstance(value, list)
      indexed = self._default_indexed
      # TODO: What if it's a list of Model instances?
      prop = GenericProperty(name, repeated=repeated, indexed=indexed)
    prop._code_name = name
    self._properties[name] = prop
    prop._set_value(self, value)

  @classmethod
  def _initial_values_from_dict(cls, value):
    '''Extract model attribute values from dict.'''
    if not isinstance(value, dict):
      raise datastore_errors.BadValueError('Expected dict, got %r.'
                                           % (value,))

    value.pop('__key__', None)
    value.pop('__id__', None)
    props_names = value.keys()
    props_code_names = {}
    for prop_key, prop in cls._properties.iteritems():
      props_code_names[prop._code_name] = prop_key
    initial_values = {}

    for key in value.iterkeys():
      _value = value[key]
      if key in props_code_names:
        prop = cls._properties[props_code_names[key]]
        if not isinstance(prop, ndb.ComputedProperty):
          if not _value is None:
            has_set_from_dict = hasattr(prop, '_set_from_dict')
            if not has_set_from_dict is None:
              initial_values[key] = prop._set_from_dict(_value)
      else:
        repeated = isinstance(value[key], list)
        prop = GenericProperty(key, repeated=repeated)
        initial_values[key] = prop._set_from_dict(_value)

    return initial_values

  def _populate_from_dict(self, json):
    '''Populates the entity with data from dict.'''
    values = self._initial_values_from_dict(json)
    props_names = [p._code_name for p in self._properties.itervalues()]
    for key, value in values.iteritems():
      if key in props_names:
        prop = get_prop(key, self._properties)
        prop._set_value(self, value)
      else:
        setattr(self, key, value)


class _ReferenceModel(Model):
  urlsafe_key = StringProperty('k')
  display = StringProperty('d')


class ReferenceProperty(StructuredProperty):
  '''Property to store references to real entities with a description of the
  entity and string that represents urlsafe key.'''
  def __init__(self, modelclass=None, display=None, is_child=True,
               allow_new=True, **kwds):
    '''Constructor.
    Args:
      modelclass: Entity model class. If no modelclass is provided, we assume
        that modelclass is the entity model class itself.
      display: property or function which returns description for the entity.
        If display is a property, it should be StringProperty.
        If display is a function, it's going to receive the entity itself as
        unique argument.
        If no display is provided, we try to get a 'display' property inside
        modelclass.
      is_child: If True, we set the parent entity of the new subentity pointing
        to main entity; else, no parent is set. If True, allow_new is set to
        True.
      allow_new: If True, we allow the creation of new entities.

    E. g.:
      class MyReferencedModel(Model):
        prop1 = ndb.StringProperty()

      class MyModel(Model):
        my_prop = ReferenceProperty(MyReferencedModel,
                                    display=MyReferencedModel.prop1)

    E. g.:
      class MyReferencedModel(Model):
        display = ndb.StringProperty()

      class MyModel(Model):
        my_prop = ReferenceProperty(MyReferencedModel)

    E. g.:
      class MyReferencedModel(Model):
        prop1 = ndb.StringProperty()

      class MyModel(Model):
        my_prop = ReferenceProperty(
          MyReferencedModel,
          display=lambda x: x.prop1 + ' says: Hello World!'
        )
    '''
    super(ReferenceProperty, self).__init__(_ReferenceModel, **kwds)
    self._display = display
    self._original_class = modelclass
    self._original = None
    if self._repeated:
      self._original = []
    self._is_child = is_child
    self._allow_new = allow_new or is_child

  def _fix_up(self, cls, code_name):
    super(ReferenceProperty, self)._fix_up(cls, code_name)
    if self._original_class is None:
      self._original_class = cls

    if self._display is None:
      try:
        self._display = getattr(self._original_class, 'display')
      except AttributeError:
        raise datastore_errors.BadValueError('No display property found.')
    else:
      if not isinstance(self._display, ndb.StringProperty) and \
          not callable(self._display):
        raise datastore_errors.BadValueError('Display argument is not valid.')

  def _set_value(self, entity, value):
    super(ReferenceProperty, self)._set_value(entity, value)
    self._original = value

  def _validate(self, value):
    if isinstance(value, dict):
      if 'urlsafe_key' in value:
        value = _ReferenceModel(**value)
      else:
        value = self._original_class.from_dict(value)
    if not isinstance(value, (self._original_class, _ReferenceModel)):
      raise datastore_errors.BadValueError(
        'Expected %s or ReferenceProperty, got %r.'
        % (self._original_class.__name__, (value,))
      )
    return value

  def _to_base_type(self, value):
    if isinstance(value, _ReferenceModel):
      return value

    urlsafe_key = ''
    display = ''
    if not value.key is None:
      urlsafe_key = value.key.urlsafe()
    if isinstance(self._display, ndb.StringProperty) or \
        isinstance(self._display, ndb.TextProperty):
      display = getattr(value, self._display._code_name)
    elif callable(self._display):
      display = self._display(value)

    return _ReferenceModel(urlsafe_key=urlsafe_key, display=display)

  def _from_base_type(self, value):
    return value

  def _set_from_dict(self, value):
    if self._repeated:
      if not isinstance(value, (list, tuple, set, frozenset)):
        raise datastore_errors.BadValueError('Expected list or tuple,'
                                             ' got %r' % (value,))
      _value = []
      for v in value:
        urlsafe_key = v.get('urlsafe_key', '') or v.get('__key__', '')
        if not urlsafe_key:
          ref = self._original_class.from_dict(v)
        else:
          ref = _ReferenceModel(urlsafe_key=urlsafe_key,
                                display=v.get('display', ''))
          display = v.get('display', None)
          if not display:
            entity = ndb.Key(urlsafe=urlsafe_key).get()
            ref = self._to_base_type(entity)
        _value.append(ref)
      return _value
    elif value is None:
      return None
    else:
      if not isinstance(value, dict):
        raise datastore_errors.BadValueError('Expected dict, got %r.'
                                             % (value,))
      urlsafe_key = value.get('urlsafe_key', '') or value.get('__key__',
                                                              '')
      if not urlsafe_key:
        ref = self._original_class.from_dict(value)
      else:
        ref = _ReferenceModel(urlsafe_key=urlsafe_key,
                              display=value.get('display', ''))
        display = value.get('display', None)
        if not display:
          entity = ndb.Key(urlsafe=urlsafe_key).get()
          ref = self._to_base_type(entity)
      return ref

  def _get_for_csv(self, instance):
    value = self._get_value(instance)
    if value is None:
      return ''
    if self._repeated:
      return ', '.join([val.display for val in value])
    return value.display

  def _get_reference(self, entity):
    '''Retrieve original model.'''
    value = self._get_value(entity)
    if value.urlsafe_key:
      return ndb.Key(urlsafe=value.urlsafe_key).get()
    return None

  @classmethod
  def _get_reference_model_from_dict(cls, value):
    '''Returns a _ReferenceModel from data dict.'''
    if not isinstance(value, dict):
      raise datastore_errors.BadValueError('Expected dict, got %r.'
                                           % (value,))
    return _ReferenceModel(**value)


Key = ndb.Key

__all__ = ['Model', 'Key', 'datastore_errors', '_ReferenceModel', 'Expando']
for _name, _object in globals().items():
  if ((_name.endswith('Property') and issubclass(_object, ndb.Property)) or
      (_name.endswith('Error') and issubclass(_object, Exception))):
    __all__.append(_name)
