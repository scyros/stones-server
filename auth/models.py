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
from webapp2_extras.appengine.auth.models import User as Webapp2_user
from webapp2_extras.appengine.auth.models import UserToken as Webapp2_token
from webapp2_extras import security

import stones


logger = logging.getLogger(__name__)
__all__ = ['BaseUser']


class UserToken(Webapp2_token):
  '''Base User Token model.'''
  user = stones.StringProperty(required=True, indexed=True)


class BaseUser(Webapp2_user, stones.Expando):
  '''Base User model.'''
  token_model = UserToken

  created = stones.DateTimeProperty(auto_now_add=True)
  updated = stones.DateTimeProperty(auto_now=True)
  active = stones.BooleanProperty(default=True)
  confirmed = stones.DateTimeProperty()
  # ID for third party authentication, e.g. 'google:username'. UNIQUE.
  auth_ids = stones.StringProperty(repeated=True)
  # Hashed password. Not required because third party authentication
  # doesn't use password.
  password = stones.StringProperty()
  type = stones.StringProperty(repeated=True)
  first_name = stones.StringProperty()
  last_name = stones.StringProperty()
  email = stones.StringProperty()

  @classmethod
  def get_user_types(cls):
    return [
      ('u', ''),
      ('admin', 'admin'),
      ('superhero', ''),
    ]

  def __unicode__(self):
    '''String representation for user model.'''
    return self.email

  @property
  def is_confirmed(self):
    return not self.confirmed is None

  def _populate_from_dict(self, json):
    '''Populates the entity with data from dict.'''
    json.pop('password', None)
    super(BaseUser, self)._populate_from_dict(json)

  def set_password(self, password):
    '''Sets user password.'''
    hashed = security.generate_password_hash(password, length=12)
    self.password = hashed

  def to_dict(self):
    rv = super(BaseUser, self).to_dict()
    rv.pop('password', None)
    rv['is_confirmed'] = self.is_confirmed
    rv['source'] = [src.split(':')[0] for src in self.auth_ids]
    return rv

  @classmethod
  def create_user(cls, auth_id, unique_properties=None, **user_values):
    '''Creates one user.'''
    _uniques = ['email']
    if isinstance(unique_properties, list) or isinstance(unique_properties, tuple):
      _uniques += list(unique_properties)
    _uniques = list(set(_uniques))
    return super(BaseUser, cls).create_user(auth_id, _uniques, **user_values)

  def delete(self):
    '''Deletes the user taking care of unique attributes deletion.'''
    delete = True

    # Delete uniques
    try:
      for auth_id in self.auth_ids:
        unique_key = stones.Key(self.unique_model,
                              '%s.auth_id:%s' % (self.__class__.__name__, auth_id))
        unique_key.delete()

      unique_key = stones.Key(self.unique_model,
                            '%s.email:%s' % (self.__class__.__name__, self.email))
      unique_key.delete()
    except Exception, err:
      logger.error(err)
      delete = False

    # Delete user tokens
    for signup_token in self.token_model.query(
      self.token_model.user == str(self.key.integer_id())):
      signup_token.key.delete_async()

    if delete:
      self.key.delete()

  @classmethod
  def create_pwd_reset_token(cls, user_id):
    '''Creates one password reset token.'''
    entity = cls.token_model.create(user_id, 'pwd_reset')
    return entity.token

  @classmethod
  def validate_pwd_reset_token(cls, user_id, token):
    '''Validates a password reset token.'''
    return cls.validate_token(user_id, 'pwd_reset', token)

  @classmethod
  def delete_pwd_reset_token(cls, user_id, token):
    '''Deletes a password reset token.'''
    cls.token_model.get_key(user_id, 'pwd_reset', token).delete()
