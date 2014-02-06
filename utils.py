#!/usr/bin/env python
#-*- coding:utf-8 -*-

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

import datetime
import logging
import base64
import random
import string
try:
  import simplejson as json
except ImportError:
  import json

import webapp2
from google.appengine.ext import ndb
from google.appengine.ext import blobstore
from google.appengine.api import files
from google.appengine.api import users as google_users
from google.appengine.api import images
from babel.support import LazyProxy
import model

import unittest
from google.appengine.ext import testbed
from google.appengine.datastore import datastore_stub_util


logger = logging.getLogger(__name__)
__all__ = ['JSONEncoder', 'clear_id', 'BaseTestCase', 'get_constant_display',
           'get_constants_choices', 'resize_image']


def get_constant_display(constant, constants_group):
  '''Extract constant display from her constants group.'''
  for item in constants_group:
    if constant == item[0]:
      return item[1]
  raise IndexError


def get_constants_choices(constants_group):
  '''Returns a list of constants.'''
  return [item[0] for item in constants_group]


def clear_id(id):
  """
    Clear id to add it to model creation.
    Converts to ascii, replace spaces, and more.
  """
  map_ = {u'ñ': 'n', u'á': 'a', u'é': 'e', u'í': u'i', u'ó': 'o', u'ú': 'u'}
  _id = id
  _id = _id.strip().lower()
  _id = _id.replace(' ', '-')
  for old, new in map_.iteritems():
    _id = _id.replace(old, new)
  return _id


class JSONEncoder(json.JSONEncoder):
  """
    Encoder for models dumps.
  """
  def __init__(self, *args, **kwargs):
    kwargs['ensure_ascii'] = True
    super(JSONEncoder, self).__init__(*args, **kwargs)

  def default(self, obj):
    if isinstance(obj, datetime.datetime) or isinstance(obj, datetime.date):
      return obj.strftime(model.DATETIME_FORMAT)
    elif isinstance(obj, datetime.date):
      return obj.strftime(model.DATE_FORMAT)
    elif isinstance(obj, datetime.time):
      return obj.strftime(model.TIME_FORMAT)
    elif isinstance(obj, ndb.Query):
      return obj.fetch()
    elif isinstance(obj, LazyProxy):
      return unicode(obj)
    elif isinstance(obj, ndb.Model):
      our_dict = obj.to_dict()
      if not '$$key$$' in our_dict and obj.key:
        our_dict['$$key$$'] = obj.key.urlsafe()
      if not '$$id$$' in our_dict and obj.key:
        our_dict['$$id$$'] = obj.key.id()
      return our_dict
    elif isinstance(obj, model.Key):
      return obj.urlsafe()
    elif isinstance(obj, google_users.User):
      return {
        'email': obj.email(),
        'user_id': obj.user_id(),
        'nickname': obj.nickname(),
      }
    else:
      return json.JSONEncoder.default(self, obj)


def resize_image(b64encoded_image, width=0, height=0):
  '''Resize an image.

    :param b64encoded_image:
    Base64 image representation.

    :returns:
    base64 encoded string representing the image.'''
  # if we deal with unprocessed base64.
  if 'data:' in b64encoded_image:
    parts = b64encoded_image.split(',')
    mimetype = parts[0].split(';')[0].split(':')[1]
    content = parts[1]
  else:
    mimetype = 'image/png'
    content = b64encoded_image

  logger.debug(mimetype)
  img = base64.decodestring(content)
  img = images.resize(image_data=img, height=height, width=width)
  img = base64.encodestring(img)
  img = ''.join(['data:', mimetype, ';base64,', img.encode('utf-8')])
  return img


class BaseTestCase(unittest.TestCase):
  '''Base class to test.'''
  def __init__(self, *args, **kwargs):
    super(BaseTestCase, self).__init__(*args, **kwargs)
    self.app = webapp2.import_string('main.app')

  def setUp(self):
    '''Activates some appengine specific stuff.'''
    self.testbed = testbed.Testbed()
    self.testbed.activate()
    # Consistency policy to HRD.
    self.policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=0)
    self.testbed.init_datastore_v3_stub(consistency_policy=self.policy)
    self.testbed.init_memcache_stub()
    self.testbed.init_user_stub()

  def tearDown(self):
    self.testbed.deactivate()
