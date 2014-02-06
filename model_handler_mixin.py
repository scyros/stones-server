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

import webapp2_extras
from .model import Key

from google.appengine.ext import ndb
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext.ndb import Property
from google.appengine.datastore.datastore_query import PropertyOrder
from google.net.proto.ProtocolBuffer import ProtocolBufferDecodeError

from .utils import *


logger = logging.getLogger(__name__)


class Error(Exception):
  '''Base class to errors'''


class NoKeyOrIdError(Error):
  '''Occurs when no key or id is provided to find a single entity.'''


class NoEntityError(Error):
  '''Occurs when is imposible to find an entity.'''


def get_entity_by_key(key):
  '''Retrieves an entity by a key.'''
  try:
    entity = Key(urlsafe=key).get()
    if not entity:
      raise NoEntityError
    return entity
  except ProtocolBufferDecodeError, e:
    raise NoEntityError


class ModelHandlerMixin(object):
  '''
    Mixin to add model CRUD to handler.
  '''
  # our model class
  model = None
  # properties to sort GET responses
  # it should be model properties, e.g., MyModel.myproperty
  ordering = []
  # model properties to be retrieved in GET responses
  # it should be strings, e.g., 'myproperty'
  GET_properties = []

  def _pre_get_hook(self):
    '''To run before GET.'''

  def _post_get_hook(self, result):
    '''To run after GET.
    result: Array with found entities to be returned.'''
    return result

  def build_filters(self, kwargs):
    '''Builds filters to retrieve entities.'''
    params = kwargs.copy()
    params.update(self.request.params)

    qry_params = []
    for param_key, param_value in params.iteritems():
      if param_value:
        try:
          attr = getattr(self.model, param_key)
          qry_params.append(attr == attr._set_from_dict(param_value))
        except:
          # i don't take care about non _set_from_dict properties and
          # inexistent model properties
          pass

    return qry_params

  def build_order(self):
    '''Builds entities sorting.'''
    rv = []
    for order in self.ordering:
      if not isinstance(order, Property) and not isinstance(order, PropertyOrder):
        continue
      rv.append(order)
    return rv

  def create_query(self, filters=[], order=[], kwargs={}):
    '''Creates the query to retrieve entities.'''
    if 'parent' in kwargs:
      parent = ndb.Key(urlsafe=kwargs['parent'])
      query = self.model.query(ancestor=parent)
    else:
      query = self.model.query()

    query = query.filter(*filters)
    query = query.order(*order)
    return query

  def limit(self, limit=None):
    '''Sets the maximum number of results retrieved by a query (GET).

    :param limit:
      Limit found in request params. "l" is a reserved query parameter to
      restrict the number of results.
    :type limit:
      integer
    '''
    if limit is None:
      return None

    try:
      limit = int(limit)
    except ValueError:
      raise ValueError('Limit should be an integer. Found %s' % limit)
    return limit

  def get(self, **kwargs):
    '''GET verb.
    Returns a list of entities, even if the result is a single entity.

    We assume 'key' or 'id' for identify one entity through url param.'''

    def cast_int(value):
      try:
        rv = int(value)
      except (ValueError, TypeError), e:
        rv = None
      return rv

    @ndb.tasklet
    def get_entities(qry, limit=None, page_size=None, page=None,
                     start_cursor=None):
      if not page_size is None:
        if not page is None:
          _entities = yield qry.fetch_async(limit,
                                            offset=(page - 1) * page_size)
        elif not start_cursor is None:
          _entities = yield qry.fetch_page_async(page_size,
                                                 start_cursor=start_cursor)
      else:
        _entities = yield qry.fetch_async(limit)
      raise ndb.Return(_entities)

    self._pre_get_hook()
    key = kwargs.pop('key', None) or self.request.get('key')
    id = kwargs.get('id', None) or self.request.get('id')
    if key:
      try:
        entities = get_entity_by_key(key)
      except NoEntityError:
        return self.abort(404, '%s not found.' % self.model.__class__.__name__)
    elif id:
      entities = self.model.get_by_id(id)
      if not entities:
        return self.abort(404, '%s not found.' % self.model.__class__.__name__)
    else:
        # No key or id. We need to return entities by query filters.
        kwargs.update(self.request.params)

        # "p" is a reserved query parameter to retrieve one page of results.
        page = kwargs.pop('p', None)
        page = cast_int(page)
        # "c" is a reserved query parameter to set next cursor for paged
        # requests.
        cursor = kwargs.pop('c', None)
        try:
          if not cursor is None:
            cursor = Cursor(urlsafe=cursor)
        except:
          cursor = None
        # "s" is a reserved query parameter to set results page size.
        page_size = kwargs.pop('s', None)
        page_size = cast_int(page_size)
        if (not cursor is None or not page is None) and page_size is None:
          page_size = 20  # Defaults to 20 results per page

        filters = self.build_filters(kwargs)
        order = self.build_order()
        qry = self.create_query(filters, order, kwargs)
        # "l" is a reserved query parameter to limit how many results should be
        # retrieved
        limit = self.limit(kwargs.get('l', None))
        if not page_size is None:
          if not page is None:
            entities = get_entities(qry, limit=limit, page=page).get_result()
            entities = {
              'entities': entities,
              'total_pages': (qry.count() / page_size) + 1,
              'page_size': page_size,
              'current_page': page,
            }
          elif not cursor is None:
            entities, cursor, more = get_entities(
              qry, limit=limit, page_size=page_size,
              start_cursor=cursor).get_result()
            entities = {
              'entities': entities,
              'total_pages': (qry.count() / page_size) + 1,
              'page_size': page_size,
              'cursor': cursor and cursor.urlsafe() or None,
            }
        else:
          entities = get_entities(qry, limit=limit).get_result()

    entities = self._post_get_hook(entities)

    return self.render_json(entities)

  def _pre_post_hook(self):
    '''To run before POST.'''

  def _post_post_hook(self, entity):
    '''To run after POST.
    entity: recently entity created.'''

  def create_model(self, **model_args):
    '''Create a new instance of model class.
    Specially for build key parents or special key ids.'''
    return self.model.from_dict(model_args)

  def post(self, **kwargs):
    '''POST verb.
    Returns a new entity created from request body as JSON formatted
    input'''
    self._pre_post_hook()
    new_entity_json = self.extract_json()
    new_entity_json.pop('$$key$$', None)
    new_entity_json.pop('$$id$$', None)
    entity = self.create_model(**new_entity_json)
    entity.put()
    self._post_post_hook(entity)

    return self.render_json(entity.to_dict())

  def _pre_put_hook(self):
    '''To run before PUT.'''

  def _post_put_hook(self, entity):
    '''To run after PUT.
    entity: recently modified entity.'''

  def update_model(self, _entity, **model_args):
    '''Update model'''
    _entity._populate_from_dict(model_args)

  def put(self, **kwargs):
    '''PUT verb.
    Modifies an entity with JSON info provided.'''
    self._pre_put_hook()
    key = kwargs.pop('key', None)
    id = self.request.get('id', None)

    if not key and not id:
      raise NoKeyOrIdError

    if key:
      try:
        entity = get_entity_by_key(key)
      except NoEntityError:
        return self.abort(404, '%s not found.' % self.model.__class__.__name__)
    elif id:
      entity = self.model.get_by_id(id)
      if not entities:
        return self.abort(404, '%s not found.' % self.model.__class__.__name__)

    entity_json = self.extract_json()
    self.update_model(entity, **entity_json)
    entity.put()
    self._post_put_hook(entity)

    return self.render_json(entity.to_dict())

  def _pre_delete_hook(self):
    '''To run before DELETE.'''

  def _post_delete_hook(self, entity):
    '''To run after DELETE.
    entity: recently deleted entity.'''

  def model_delete(self, entity):
    '''Deletion function.
    Useful if you don't want to delete the entity, just mark it as
    disabled.
    entity: entity to be deleted.'''
    entity.key.delete_async()

  def delete(self, **kwargs):
    '''DELETE verb.
    Deletes an entity.'''
    self._pre_delete_hook()
    key = kwargs.pop('key', None)
    id = self.request.get('id', None)

    if not key and not id:
      raise NoKeyOrIdError

    if key:
      entity = Key(urlsafe=key).get()
    elif id:
      self.model.get_by_id(id)

    if entity is None:
      return self.abort(404, '%s not found.' % self.model.__class__.__name__)

    self.model_delete(entity)
    self._post_delete_hook(entity)

    self.response.status = 200
    self.response.write(u'Model deletion successful')
