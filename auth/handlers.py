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
import datetime

import stones
import stones.oauth2 as oauth2

from google.appengine.api import mail
from google.appengine.api import taskqueue

import webapp2
import webapp2_extras.auth


logger = logging.getLogger(__name__)
__all__ = ['get_config',
           'AuthError',
           'ProviderConfNotFoundError',
           'BaseWelcomeHandler',
           'BaseOAuth2CallbackHandler',
           'BaseUserModelHandler',
           'BaseUserTypesHandler',
           'BaseOAuth2BeginHandler',
           'BaseUserAuthProvidersHandler',
           'BaseMakeSuperHeroHandler',
           'BaseLogoutHandler',
           'BaseSignupHandler',
           'BaseAccountVerificationEmailHandler',
           'BaseAccountVerificationHandler',
           'BaseLoginHandler',
           'BasePasswordReset1Handler',
           'BasePasswordResetSendHandler',
           'BasePasswordResetEmailHandler',
           'BasePasswordReset2Handler']

AUTH_CONFIG = {
  'providers': {},
  'templates': {
    'login': 'auth/login.html',
    'welcome': 'auth/welcome.html',
    'signup': 'auth/signup.html',
    'welcome_text': 'auth/welcome_email.txt',
    'welcome_html': 'auth/welcome_email.html',
    'verify_account': 'auth/verify_account.html',
    'password_reset_1': 'auth/password_reset_1.html',
    'password_reset_send': 'auth/password_reset_send.html',
    'password_reset_2': 'auth/password_reset_2.html',
    'password_reset_text': 'auth/password_reset_email.txt',
    'password_reset_html': 'auth/password_reset_email.html',
  },
  'email_sender': None,
}


class AuthError(Exception):
  '''Error base class for module.'''


class ProviderConfNotFoundError(AuthError):
  '''Provider configuration not found in app settings.'''


def get_config():
  # Get config to this module
  app = webapp2.get_app()
  try:
    config = app.config.load_config('stones.auth',
      default_values=AUTH_CONFIG,
      required_keys=['templates', 'email_sender'])
    templates = config['templates']
    email_sender = config['email_sender']
  except KeyError, e:
    try:
      app.config.loaded.remove('stones.auth')
    except Exception, e:
      pass
    config = get_config()
  return config


class WebAppBaseHandler(stones.BaseHandler):
  '''Base handler to manage pages which their page titles and angular app
  should be modified.'''
  page_title = u'Page Title to ...'
  angular_app = 'stones.auth'
  tpl_key = ''

  def __init__(self, *args, **kwargs):
    super(WebAppBaseHandler, self).__init__(*args, **kwargs)
    config = get_config()
    try:
      self._tpl_name = config['templates'][self.tpl_key]
    except KeyError, e:
      self._tpl_name = AUTH_CONFIG['templates'][self.tpl_key]

  def get(self):
    context = {
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
    }
    self.render_response(self._tpl_name, **context)


class BaseWelcomeHandler(WebAppBaseHandler):
  '''Base Welcome Interface.'''
  tpl_key = 'welcome'


class BaseLogoutHandler(stones.BaseHandler):
  '''Base Logout handler.'''
  def get(self):
    self.auth.unset_session()
    # TODO: Clear tokens?
    return self.redirect_to('home')
  post = get


class OAuth2Conf(stones.BaseHandler):
  '''Base class to handler that must be granted access to settings to find info
  about auth configuration.'''

  # Scope for actions.
  scope = ''

  def get_provider_conf(self, provider_name):
    '''Gets provider configuration.'''
    conf = get_config()
    if not conf:
      raise ProviderConfNotFoundError('No configuration found in settigs.')
    try:
      providers = conf['providers']
    except KeyError:
      raise ProviderConfNotFoundError(
        'No providers key found in Oauth2 settings.')
    try:
      provider = providers[provider_name]
    except KeyError:
      raise ProviderConfNotFoundError(
        'Provider "%s" not found in Oauth2 providers' % provider_name)
    return provider


class BaseOAuth2CallbackHandler(OAuth2Conf):
  '''Handler to handle Oauth2 request callback from provider.'''
  def create_user(self, provider, user_info):
    '''Create a new user'''
    user_model = self.auth.store.user_model
    return user_model.create_user(':'.join([provider, user_info['email']]),
                                  **user_info)

  def get_user(self, provider, user_info):
    '''Find a user by provider and user info.'''
    user_model = self.auth.store.user_model
    user = user_model.get_by_auth_id(':'.join([provider, user_info['email']]))
    if user:
      return False, user
    else:
      user = user_model.query(user_model.email == user_info['email']).get()
      if user:
        return True, user
    return None, None

  def get_user_dict(self, user):
    '''Convert a user model into webapp2_extras.auth user dict.'''
    return self.auth.store.user_to_dict(user)

  def get(self, provider=None):
    code = self.request.get('code', None)
    if not code:
      return self.redirect_to('oauth2.begin', provider=provider)
      #TODO: Add logic to manage declined permissions
    state = self.request.get('state', None)
    come_back_to = ''
    if state and '|' in state:
      come_back_to = state.split('|')[-1]

    oauth2_conf = self.get_provider_conf(provider)
    redirect_uri = self.uri_for('oauth2.callback', provider=provider,
                                _full=True)
    service = oauth2.get_service(provider)(redirect_uri=redirect_uri,
                                           **oauth2_conf)
    token = service.get_access_token(code)
    user_info = service.get_user_info(token)

    add_auth_id, user = self.get_user(provider, user_info)
    if not user:
      # creates a new one
      user_info['type'] = ['u']
      ok, user = self.create_user(provider, user_info)

      if ok:
        user.confirmed = datetime.datetime.now()
        user.put_async()
        user = self.get_user_dict(user)
        self.auth.set_session(user)
        if come_back_to:
          return self.redirect(come_back_to)
        return self.redirect_to('home')
      else:
        raise AuthError('Username already taken.')
    else:
      if add_auth_id:
        auth_ids = user.auth_ids
        new_auth_id = ':'.join([provider, user_info['email']])
        auth_ids.append(new_auth_id)
        user.auth_ids = auth_ids
        user.put_async()
        unique_key = '%s.%s:%s' % (user.__class__.__name__, 'auth_id', new_auth_id)
        unique = user.unique_model.create(unique_key)

      if not user.active:
        self.abort(401, 'Inactive User.')

      user = self.get_user_dict(user)
      self.auth.set_session(user)
      if come_back_to:
        return self.redirect(come_back_to)
      return self.redirect_to('home')


class BaseOAuth2BeginHandler(OAuth2Conf):
  '''Handler to begin OAuth2 authentification process.'''
  def get(self, provider=None):
    oauth2_conf = self.get_provider_conf(provider)
    redirect_uri = self.uri_for('oauth2.callback', provider=provider,
                                _full=True)
    service = oauth2.get_service(provider)(redirect_uri=redirect_uri,
                                           **oauth2_conf)

    come_back_to = self.request.get('come_back_to', '')
    auth_url = service.get_authorization_url(come_back_to=come_back_to)
    return self.redirect(auth_url)

  def post(self, provider=None):
    oauth2_conf = self.get_provider_conf(provider)
    redirect_uri = self.uri_for('oauth2.callback', provider=provider,
                                _full=True)
    service = oauth2.get_service(provider)(redirect_uri=redirect_uri,
                                           **oauth2_conf)

    come_back_to = self.request.get('come_back_to', '')
    auth_url = service.get_authorization_url(come_back_to=come_back_to)
    return self.response.write(auth_url)


class BaseSignupHandler(WebAppBaseHandler):
  '''Signup Interface.'''
  tpl_key = 'signup'

  def post(self):
    JSONAPI = True
    try:
      # User creation through JSON API
      user = self.extract_json()
    except ValueError:
      # User creation through HTML Form
      user = {'username': self.request.get('username', '')}
      JSONAPI = False

    if not 'username' in user or not user['username']:
      return self.abort(400, 'Username is mandatory.')

    # we assume that usernames are valid emails
    if not mail.is_email_valid(user['username']):
      return self.abort(400, 'Username is not valid. It must be an email.')

    username = user.pop('username')
    user_model = self.auth.store.user_model
    auth_id = ':'.join(['own', username])
    user['email'] = username
    if not 'type' in user or not isinstance(user['type'], list):
      user['type'] = ['u']
    if not 'u' in user['type']:
      user['type'].append('u')

    ok, new_user = user_model.create_user(auth_id, **user)
    if ok:
      signup_token = user_model.create_signup_token(new_user.key.id())
      taskqueue.add(
        url=self.uri_for('send.account.verification',
                         user_id=new_user.key.id()),
        params={'signup_token': signup_token},
        method='POST'
      )
      if JSONAPI:
        return self.render_json(new_user)
      else:
        config = get_config()
        context = {'user': new_user}
        return self.render_response(config['templates']['welcome'], **context)

    else:
      return self.abort(500, 'Username already taken. Username must be unique.')


class BaseAccountVerificationEmailHandler(stones.BaseHandler):
  '''Handler to begin account verification process.'''
  def post(self, user_id=None):
    config = get_config()

    signup_token = self.request.get('signup_token')
    user = self.auth.store.user_model.get_by_id(int(user_id))

    context = {
      'host': self.request.host_url,
      'verify_url': self.uri_for('verify.account', signup_token=signup_token,
        user_id=user_id, _full=True),
    }

    email = mail.EmailMessage(sender=config['email_sender'])
    email.subject = u'Alta en el sistema'
    email.to = user.email
    email.body = self.jinja2.render_template(
      config['templates']['welcome_text'], **context)
    email.html = self.jinja2.render_template(
      config['templates']['welcome_html'], **context)
    email.send()


class BaseAccountVerificationHandler(WebAppBaseHandler):
  '''Handler to finish account verification process.'''
  tpl_key = 'verify_account'
  user_activation = False

  def get(self, signup_token=None):
    user_id = int(self.request.get('user_id'))

    valid_token = self.auth.store.user_model.validate_signup_token(
      user_id, signup_token)
    context = {
      'user_id': user_id,
      'verify_url': self.uri_for('verify.account', signup_token=signup_token,
        user_id=user_id),
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
      'user': self.auth.store.user_model.get_by_id(user_id),
    }
    if valid_token:
      return self.render_response(self._tpl_name, **context)
    else:
      self.abort(403, 'Invalid Token.')

  def verify_user_info(self, user_info):
    '''Verify user info.'''
    return True, {}

  def post(self, signup_token=None):
    user_id = int(self.request.get('user_id'))

    valid_token = self.auth.store.user_model.validate_signup_token(
      user_id, signup_token)
    context = {
      'user_id': user_id,
      'verify_url': self.uri_for('verify.account', signup_token=signup_token,
        user_id=user_id),
      'errors': {},
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'user': self.auth.store.user_model.get_by_id(user_id),
    }
    if valid_token:
      password = self.request.get('password')
      confirm = self.request.get('confirm')
      first_name = self.request.get('first_name')
      last_name = self.request.get('last_name')

      if not password:
        # TODO: Localize error messages
        context['errors']['password'] = u'Contraseña no válida'
      if not confirm:
        # TODO: Localize error messages
        context['errors']['confirm'] = u'Confirmación de Contraseña no válida'
      if password and confirm and password != confirm:
        # TODO: Localize error messages
        context['errors']['confirm'] = u'Contraseña y Confirmación no coinciden'

      if context['errors']:
        return self.render_response(self._tpl_name, **context)

      user_info = dict(self.request.params)
      user_info.pop('password')
      user_info.pop('confirm')

      valid_user, reasons = self.verify_user_info(user_info)
      if not valid_user:
        context['errors'].update(reasons)
        return self.render_response(self._tpl_name, **context)

      user = self.auth.store.user_model.get_by_id(user_id)
      user.set_password(password)
      user.populate(**user_info)
      user.confirmed = datetime.datetime.now()
      if self.user_activation:
        user.active = True
      user.put_async()
      user.delete_signup_token(user_id, signup_token)
      user = self.auth.store.user_to_dict(user)
      self.auth.set_session(user)
      return self.redirect_to('home')
    else:
      self.abort(403, 'Invalid Token.')


class BasePasswordReset1Handler(WebAppBaseHandler):
  '''Handler to begin password reset process.'''
  tpl_key = 'password_reset_1'

  def get(self):
    context = {
      'pwd_reset_url': self.uri_for('password.reset.1'),
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
    }
    return self.render_response(self._tpl_name, **context)

  def post(self):
    errors = {}
    user_email = self.request.get('user_email')
    if not user_email:
      # TODO: Localize error messages
      errors['user_email'] = u'Correo electrónico no válido'
    else:
      user = self.auth.store.user_model.query(
        stones.GenericProperty('email') == user_email).get()
      if not user:
        # TODO: Localize error messages
        errors['user_email'] = u'Usuario no existente'

    if errors:
      context = {
        'pwd_reset_url': self.uri_for('password.reset.1'),
        'angular_app': self.angular_app,
        'page_title': self.page_title,
        'errors': errors,
      }
      return self.render_response(self._tpl_name, **context)
    else:
      user_id = user.get_id()
      user_model = self.auth.store.user_model
      pwd_reset_token = user_model.create_pwd_reset_token(user_id)
      taskqueue.add(
        url=self.uri_for('send.password.reset', user_id=user_id),
        params={'pwd_reset_token': pwd_reset_token},
        method='POST'
      )
      return self.redirect_to('password.reset.send')


class BasePasswordResetSendHandler(WebAppBaseHandler):
  '''Handler to notify password reset email was send.'''
  tpl_key = 'password_reset_send'

  def get(self):
    context = {
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
    }
    return self.render_response(self._tpl_name, **context)


class BasePasswordResetEmailHandler(stones.BaseHandler):
  '''Handler to send password reset email.'''
  def post(self, user_id=None):
    config = get_config()

    pwd_reset_token = self.request.get('pwd_reset_token')
    user = self.auth.store.user_model.get_by_id(int(user_id))

    context = {
      'host': self.request.host_url,
      'pwd_reset_url': self.uri_for('password.reset.2',
        pwd_reset_token=pwd_reset_token, user_id=user_id, _full=True),
    }

    email = mail.EmailMessage(sender=config['email_sender'])
    email.to = user.email
    email.subject = u'Cambio de contraseña'
    email.body = self.jinja2.render_template(
      config['templates']['password_reset_text'], **context)
    email.html = self.jinja2.render_template(
      config['templates']['password_reset_html'], **context)
    email.send()


class BasePasswordReset2Handler(WebAppBaseHandler):
  '''Handler to finish password reset process.'''
  tpl_key = 'password_reset_2'

  def get(self, pwd_reset_token=None):
    user_id = int(self.request.get('user_id'))

    valid_token = self.auth.store.user_model.validate_pwd_reset_token(
      user_id, pwd_reset_token)
    context = {
      'user_id': user_id,
      'pwd_reset_url': self.uri_for('password.reset.2',
        pwd_reset_token=pwd_reset_token, user_id=user_id),
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
    }
    if valid_token:
      return self.render_response(self._tpl_name, **context)
    else:
      self.abort(403, 'Invalid Token.')

  def post(self, pwd_reset_token=None):
    user_id = int(self.request.get('user_id'))

    valid_token = self.auth.store.user_model.validate_pwd_reset_token(
      user_id, pwd_reset_token)
    context = {
      'user_id': user_id,
      'pwd_reset_url': self.uri_for('password.reset.2',
        pwd_reset_token=pwd_reset_token, user_id=user_id),
      'errors': {},
      'angular_app': self.angular_app,
      'page_title': self.page_title,
    }
    if valid_token:
      password = self.request.get('password')
      confirm = self.request.get('confirm')

      if not password:
        # TODO: Localize error messages
        context['errors']['password'] = u'Contraseña no válida'
      if not confirm:
        # TODO: Localize error messages
        context['errors']['confirm'] = u'Confirmación de Contraseña no válida'
      if password and confirm and password != confirm:
        # TODO: Localize error messages
        context['errors']['confirm'] = u'Contraseña y Confirmación no coinciden'

      if context['errors']:
        return self.render_response(self._tpl_name, **context)

      user = self.auth.store.user_model.get_by_id(user_id)
      user.set_password(password)
      user.put_async()
      user.delete_pwd_reset_token(user_id, pwd_reset_token)
      return self.redirect_to('login')
    else:
      self.abort(403, 'Invalid Token.')


class BaseLoginHandler(WebAppBaseHandler):
  '''Login Interface.'''
  tpl_key = 'login'
  def get(self):
    self_url = self.request.route.build(self.request, self.request.route_args,
        self.request.route_kwargs)
    come_back_to = self.request.get('come_back_to')
    context = {
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
      'login_url': self_url,
      'signup_url': self.uri_for('signup'),
      'come_back_to': come_back_to,
    }
    return self.render_response(self._tpl_name, **context)

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')

    self_url = self.request.route.build(self.request, self.request.route_args,
        self.request.route_kwargs)
    come_back_to = self.request.get('come_back_to')
    context = {
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
      'login_url': self_url,
      'come_back_to': come_back_to,
      'signup_url': self.uri_for('signup'),
    }

    try:
      user = self.auth.store.user_model.get_by_auth_id(':'.join(['own', username]))
      if user and user.password:
        user = self.auth.get_user_by_password(':'.join(['own', username]),
          password)
        if user.get('user_id'):
          user_model = self.auth.store.user_model.get_by_id(user['user_id'])
          if not user_model.active:
            raise webapp2_extras.auth.InvalidAuthIdError
        self.auth.set_session(user)
        return self.redirect_to('home')
      else:
        raise webapp2_extras.auth.InvalidAuthIdError
    except (webapp2_extras.auth.InvalidAuthIdError,
      webapp2_extras.auth.InvalidPasswordError), e:
      # TODO: Localize error messages
      context['errors'] = u'Nombre de usuario o contraseña incorrectos'
      return self.render_response(self._tpl_name, **context)



class BaseMakeSuperHeroHandler(OAuth2Conf):
  '''Handler to make one user super hero.'''
  def get(self):
    user_model = self.auth.store.user_model
    qry = user_model.query(user_model.type == 'superhero')
    superheros = qry.count()
    if superheros == 0:
      if self.user:
        user_type = self.user.type
        user_type.append('superhero')
        self.user.type = user_type
        self.user.put()
      return self.redirect_to('home')
    raise AuthError('You have no honor! You cannot be a superhero!')


class BaseUserModelHandler(stones.BaseHandler, stones.ModelHandlerMixin):
  '''Base Handler to manage User model CRUD.'''
  def __init__(self, *args, **kwargs):
    super(BaseUserModelHandler, self).__init__(*args, **kwargs)
    self.model = self.auth.store.user_model

  def build_filters(self, kwargs):
    filters = super(BaseUserModelHandler, self).build_filters(kwargs)

    if 'type' in kwargs:
      filters.append(self.model.type == kwargs['type'])

    return filters

  def create_model(self, **model_args):
    rejected_attrs  = ('auth_ids', 'created', 'confirmed', 'is_confirmed',
      'updated')
    for attr in rejected_attrs:
      model_args.pop(attr, None)

    auth_id = model_args.get('email', None)
    if not auth_id:
      raise AuthError('No email provided.')
    auth_id = 'own:' + auth_id
    model_args['source'] = 'own'
    password = model_args.pop('password', None)
    if password:
      model_args['password_raw'] = password

    ok, new_user = self.model.create_user(auth_id, **model_args)
    if ok:
      signup_token = self.model.create_signup_token(new_user.key.id())
      taskqueue.add(
        url=self.uri_for('send.account.verification',
                         user_id=new_user.key.id()),
        params={'signup_token': signup_token},
        method='POST'
      )
      return new_user
    else:
      raise AuthError('Impossible to create this user.')
    return

  def update_model(self, _entity, **model_args):
    rejected_attrs  = ('auth_ids', 'email', 'created', 'confirmed',
      'is_confirmed', 'source', 'updated')
    for attr in rejected_attrs:
      model_args.pop(attr, None)
    super(BaseUserModelHandler, self).update_model(_entity, **model_args)

  def model_delete(self, entity):
    entity.active = False
    entity.put_async()


class BaseUserTypesHandler(stones.ConstantHandler):
  '''Base handler to retrieve User Types.'''
  def __init__(self, *args, **kwargs):
    super(BaseUserTypesHandler, self).__init__(*args, **kwargs)
    self.constant = self.auth.store.user_model.get_user_types()


class BaseUserAuthProvidersHandler(stones.ConstantHandler):
  '''Base handler to retrieve User auth providers.'''
  own_auth_provider_display = 'Own'

  def __init__(self, *args, **kwargs):
    super(BaseUserAuthProvidersHandler, self).__init__(*args, **kwargs)
    conf = get_config()
    try:
      conf = conf['providers']
    except KeyError, e:
      conf = {}

    conf['own'] = {
      'display': self.own_auth_provider_display,
    }
    providers = []
    for provider in conf:
      providers.append((provider, conf[provider].get('display', provider)))

    self.constant = tuple(providers)

