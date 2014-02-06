#!/usr/bin/env python
#-*- coding: utf-8 -*-

import logging
import datetime

import stones
import stones.oauth2 as oauth2

from google.appengine.api import mail
from google.appengine.api import taskqueue

import webapp2_extras.auth


logger = logging.getLogger(__name__)
__all__ = ['AuthError', 'ProviderConfNotFoundError', 'BaseWelcomeHandler',
           'BaseOAuth2CallbackHandler', 'BaseUserModelHandler',
           'BaseUserTypesHandler', 'BaseOAuth2BeginHandler',
           'BaseUserAuthProvidersHandler', 'BaseMakeSuperHeroHandler',
           'BaseLogoutHandler', 'BaseSignupHandler',
           'BaseAccountVerificationEmailHandler',
           'BaseAccountVerificationHandler', 'BaseLoginHandler',
           'BasePasswordReset1Handler', 'BasePasswordResetSendHandler',
           'BasePasswordResetEmailHandler', 'BasePasswordReset2Handler']

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
  'email_sender': 'foo@bar.com',
}


class AuthError(Exception):
  '''Error base class for module.'''


class ProviderConfNotFoundError(AuthError):
  '''Provider configuration not found in app settings.'''


class WebAppBaseHandler(stones.BaseHandler):
  '''Base handler to manage pages which their page titles and angular app
  should be modified.'''
  page_title = u'Page Title to ...'
  angular_app = 'stones.auth'
  tpl_key = ''

  def __init__(self, *args, **kwargs):
    super(WebAppBaseHandler, self).__init__(*args, **kwargs)
    config = self.app.config.load_config('stones.auth',
      default_values=AUTH_CONFIG,
      required_keys=['templates'])
    self._tpl_name = config['templates'][self.tpl_key]

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
    conf = self.app.config.load_config('stones.auth')
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
  def get(self, provider=None):
    code = self.request.get('code', None)
    if not code:
      return self.redirect_to('oauth2.begin', provider=provider)
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
    user_model = self.auth.store.user_model
    user = user_model.get_by_auth_id(':'.join([provider, user_info['email']]))
    user = self.auth.store.user_to_dict(user)
    if not user:
      # creates a new one
      user_info['type'] = ['u']
      ok, user = user_model.create_user(':'.join([provider, user_info['email']]),
                                        **user_info)
      if ok:
        user.confirmed = datetime.datetime.now()
        user.put_async()
        user = self.auth.store.user_to_dict(user)
        self.auth.set_session(user)
        if come_back_to:
          return self.redirect(come_back_to)
        return self.redirect_to('home')
      else:
        raise AuthError('Username already taken.')
    else:
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


class BaseSignupHandler(WebAppBaseHandler):
  '''Signup Interface.'''
  tpl_key = 'signup'

  def post(self):
    username = self.request.get('username')

    context = {
      'angular_app': self.angular_app,
      'page_title': self.page_title,
      'errors': {},
    }
    if not mail.is_email_valid(username):
      # TODO: Localize error messages
      context['errors']['username'] = u'Nombre de usuario no válido.'

    if context['errors']:
      context['username'] = username
      return self.render_response(self._tpl_name, **context)

    user_model = self.auth.store.user_model
    auth_id = ':'.join(['own', username])
    user_info = {
      'email': username,
      'type': ['u'],
    }
    ok, new_user = user_model.create_user(auth_id, **user_info)
    if ok:
      signup_token = user_model.create_signup_token(new_user.key.id())
      taskqueue.add(
        url=self.uri_for('send.account.verification', user_id=new_user.key.id()),
        params={'signup_token': signup_token},
        method='POST'
      )
      return self.redirect_to('welcome')
    else:
      context['username'] = username
      # TODO: Localize error messages
      context['errors']['username'] = u'Nombre de usuario ya existente.'
      return self.render_response(self._tpl_name, **context)


class BaseAccountVerificationEmailHandler(stones.BaseHandler):
  '''Handler to begin account verification process.'''
  def post(self, user_id=None):
    config = self.app.config.load_config('stones.auth',
      default_values=AUTH_CONFIG,
      required_keys=['email_sender', 'templates'])

    signup_token = self.request.get('signup_token')
    user = self.auth.store.user_model.get_by_id(int(user_id))

    context = {
      'verify_url': self.uri_for('verify.account', signup_token=signup_token,
        user_id=user_id, _full=True),
    }

    email = mail.EmailMessage(sender=config['email_sender'])
    email.to = user.email
    email.body = self.jinja2.render_template(
      config['templates']['welcome_text'], **context)
    email.html = self.jinja2.render_template(
      config['templates']['welcome_html'], **context)
    email.send()


class BaseAccountVerificationHandler(WebAppBaseHandler):
  '''Handler to finish account verification process.'''
  tpl_key = 'verify_account'

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
    }
    if valid_token:
      return self.render_response(self._tpl_name, **context)
    else:
      self.abort(403, 'Invalid Token.')

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
      if not first_name:
        # TODO: Localize error messages
        context['errors']['first_name'] = u'Tu nombre es obligatorio'
      if not last_name:
        # TODO: Localize error messages
        context['errors']['last_name'] = u'Tu apellido es obligatorio'

      if context['errors']:
        return self.render_response(self._tpl_name, **context)

      user = self.auth.store.user_model.get_by_id(user_id)
      user.set_password(password)
      user.confirmed = datetime.datetime.now()
      user.first_name = first_name
      user.last_name = last_name
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
      errors['email'] = u'Contraseña no válida'
    else:
      user = self.auth.store.user_model.query(
        stones.GenericProperty('email') == user_email).get()
      if not user:
        # TODO: Localize error messages
        errors['email'] = u'Usuario no existente'

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
      pwd_reset_token = self.auth.store.create_pwd_reset_token(user_id)
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
    config = self.app.config.load_config('stones.auth',
      default_values=AUTH_CONFIG,
      required_keys=['email_sender', 'templates'])

    pwd_reset_token = self.request.get('pwd_reset_token')
    user = self.auth.store.user_model.get_by_id(int(user_id))

    context = {
      'pwd_reset_url': self.uri_for('password.reset.2',
        pwd_reset_token=pwd_reset_token, user_id=user_id, _full=True),
    }

    email = mail.EmailMessage(sender=config['email_sender'])
    email.to = user.email
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
      user = self.auth.get_user_by_password(':'.join(['own', username]),
        password)
      self.auth.set_session(user)
      return self.redirect_to('home')
    except (webapp2_extras.auth.InvalidAuthIdError,
      webapp2_extras.auth.InvalidPasswordError), e:
      # TODO: Localize error messages
      context['errors'] = u'Nombre de usuario o contraseña incorrectos'
      return self.render_response(self._tpl_name, **context)


class BaseMakeSuperHeroHandler(OAuth2Conf):
  '''Handler to make one user super hero.'''
  users_allowed = ['u']
  def get(self):
    user_model = self.auth.store.user_model
    qry = user_model.query(user_model.type == 'superhero')
    superheros = qry.count()
    if superheros == 0:
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

  def update_model(self, _entity, **model_args):
    rejected_attrs  = ('auth_ids', 'email', 'created', 'confirmed',
      'is_confirmed', 'source', 'updated')
    for attr in rejected_attrs:
      model_args.pop(attr, None)
    super(BaseUserModelHandler, self).update_model(_entity, **model_args)


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
    conf = self.app.config.load_config('stones.auth',
                                            required_keys=['providers'])
    conf = conf['providers']
    conf['own'] = {
      'display': self.own_auth_provider_display,
    }
    providers = []
    for provider in conf:
      providers.append((provider, conf[provider].get('display', provider)))

    self.constant = tuple(providers)

