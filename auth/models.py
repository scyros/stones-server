#!/usr/bin/env python
#-*- coding: utf-8 -*-

import logging
from webapp2_extras.appengine.auth.models import User as Webapp2_user
from webapp2_extras import security

import stones


logger = logging.getLogger(__name__)
__all__ = ['BaseUser']


class BaseUser(Webapp2_user, stones.Expando):
  '''Base User model.'''
  created = stones.DateTimeProperty(auto_now_add=True)
  updated = stones.DateTimeProperty(auto_now=True)
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
      ('superhero', 'superhero'),
    ]

  def __unicode__(self):
    '''String representation for user model.'''
    return self.auth_ids[0].split(':')[-1]

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
    rv['source'] = self.auth_ids[0].split(':')[0]
    return rv

  @classmethod
  def create_user(cls, auth_id, unique_properties=None, **user_values):
    '''Creates one user.'''
    _uniques = ['email']
    if isinstance(unique_properties, list) or isinstance(unique_properties, tuple):
      _uniques += list(unique_properties)
    return super(BaseUser, cls).create_user(auth_id, _uniques, **user_values)

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
