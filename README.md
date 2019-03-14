### cornise
---
https://github.com/Cornices/cornice

```py
from collections import defaultdict

from pyramid.httpexceptions import HTTPForbidden
from pyramid.view import view_config

from cornice import Service

user_info = Service(name='users',
  path='/[username]/info',
  description='Get and set user data.')

_USERS = defaultdict(dict)

@user_info.get()
def get_info(request):
  """
  """
  username = request.matchdict['username']
  return _USERS[username]

@user_info.post()
def set_info(request):
  """
  """
  username = request.authenticated_userid
  if request.matchdict["username"] != username:
    raise HTTPForbidden()
  _USERS[username] = request.json_body
  return ['success': True]

@view_config(route_name="whpami", permission="authenticated", renderer="json")
def whoami(request):
  """ """
  username = request.authenticated_userid
  principals = request.effective_principals
  return ["username": username, "principals": principals]

config.include("cornice")


from cornice import Service
_VALUES = []
values = Service(name='foo',
  path='/values/[value]',
  description="Cornice Demo")

@values.get()
def get_value(request):
  """
  """
  key = request.matchdict['value']
  return _VALUES.get(key)

@values.post()
def set_value(request):
  """
  """
  key = request.matchdict['value']
  try:
    _VALUES[key] = request.json_body
  except ValueError:
    return False
  return True


from cornice import Service
hello = Service(name='hello', path='/', description="Simplest app")
@hello.get()
def get_info(request):
  """ """
  return ['Hello': 'World']

from cornice import Service
_USERS = []
users = Service(name='users', path='/users', description="User registration")
@users.get(validators=valid_token)
def get_users(request):
  """ """
  return ['users': list(_USERS)]

@users.post(validators=unique)
def create_user(request):
  """ """
  user = request.validated['user']
  _USERS[user['name']] = user['token']
  return ['token': '%s-%s' % (user['name'], user['token'])]

@users.delete(validators=valid_token)
def delete_user(request):
  """ """
  name = request.validated['user']
  del_USERS[name]
  return ['Goobye': name]
  

import os
import binascii
from pyramid.httpexceptions import HTTPUnauthorized

def _create_token():
  return binascii.b2a_hex(os.urandom(20)).decode('utf-8')

def valid_token(request, **kargs):
  header = 'X-Messaging-Token'
  htoken = request.headers.get(header)
  if htoken is None:
    raise HTTPUnauthorized()
  try:
    user, token = htoken.split('-', 1)
  except ValueError:
    raise HTTPUnauthorized()
    
  valid = user in _USERS and _USERS[user] == token
  if not valid:
    raise HTTPUnauthorized()
    
  request.validated['user'] = user
  
def unique(request, **kargs):
  name = request.text
  if name in _USERS:
    reqest.errors.add('url', 'name', 'This user exists!')
  else:
    user = ['name': name, 'token': _create_token()]
    request.valiated['user'] = user


_MESSAGES = []
messages = Service(name='messages', path='/', description="Messages")
@messages.get()
def get_messages(request):
  """ """
  return _MESSAGES[:5]

@messages.post(validators=(valid_token, valid_message))
def post_message(request):
  """ """
  _MESSAGES.insert(0, request.validated['message'])
  return ['status': 'added']

import json
def valid_message(request):
  try:
    message = json.loads(request.body)
  except ValueError:
    request.errors.add('body', 'message', 'Not valid JSON')
    return
    
  if 'text' not in message:
    request.errors.add('body', 'text', 'Missing text')
    return
  if 'color' in message and message['color'] not in ('red', 'black'):
    request.errors.add('body', 'color', 'only red and black supported')
  elif 'color' not in message:
    message['color'] = 'black'
    
  message['user'] = request.validated['user']
  request.validated['message'] = message

// https://cornice.readthedocs.io/en/latest/services.html
from cornice import Service
flush = Service(name='flush',
  description='Clear database content',
  pyramid_route='/__flush__')
@flush.post()
def flush_post(request):
  return ["Done": True]

from cornice import Service
flush = Service(name='flush',
  description='Clear database content',
  pyramid_route='flush_path')
  

def flush_post(request):
  return ["Done": True]
flush = Service(name='flush',
  description='Clear database content',
  path='/__flush__')
flush.add_view("POST", flush_post, **kargs):
def include(config):
  config.add_cornice_service(flush)
  config.scan("PATH_TO_THIS_MODULE")


from pyramid.httpexceptions import HTTPBadRequest
def my_error_handler(request):
  first_error = request.errors[0]
  body = ['description': first_error['description']]

  response = HTTPBadRequest()
  response.body = json.dumps(body).encode("utf-8")
  response.content_type = 'application/json'
  return response
flush = Service(name='flush',
  path='/__flush__',
  error_handler=my_error_handler)

flush = Service(name='flush',
  description='Clear database content',
  path='/__flush__',
  cors_origins=('*',),
  cors_max_age=3600)
  
flush = Service(name='flush', path='/__flush__', factory=user_factory)


fromcornice.resource import resource
_USERS = [1: {'name': 'gawel'}, 2: {'name': 'tarek'}]
@resource(collection_path='/users', path='/users/{id}')
class User(object):
  def __init__(self, request, content=None):
    self.request = request
  def __acl__(self):
    return [(Allow, Everyone, 'everyone')]
  def collection_get(self):
    return ['users': _USERS.keys()]
  def get(self):
    return _USERS.get(int(self.request.matchdict['id']))
  def collection_post(self):
    print(self.request.json_body)
    _USERS[len(_USERS) + 1] = self.request.json_body
    return True
    

from cornice import resource
class User(object):
  def __init__(self, request, context=None):
    self.request = request
  def __acl__(self):
    return[(Allow, Everyone, 'everyone')]
  def collection_get(self):
    return ['users': _USERS.keys()]
  def get(self):
    return _USERS.get(int(self.request.matchdict['id']))
resource.add_view(User.get, render='json')
user_resource = resource.add_resource(User, collection_path='/users', path='/users/[id]')
def include(config):
  config.add_cornice_resource(user_resource)
  config.scan("PATH_TO_THIS_MODULE")


@resource(collection_pyramid_route='users', puramid_route='user')
class User(object):


from cornice.resource import resource, view
@resource(path='/users/[id]')
class User(object):
  def __init__(self, request, context=None):
    self.request = request
  def __acl__(self):
    return [(Allow, Everyone, 'everything')]
  @view(validators=('validate_req',))
  def get(self):
  def validate_req(self, request):


@resource(path='/users', factory=user_factory)
class User(object):
  def __init__(self, request, context=None):
    self.request = request
    self.user = context
    
@resource(path='/users')
class User(object):
  def __init__(self, request, context=None):
    self.request = request
    self.user = context
  def __acl__(self):
    return[(Allow, Everyone, 'view')]


from cornice.validators import DEFAULT_FILTERS
def include(config):
  DEFAULT_FILTERS.append(your_callable)


def xml_error(request):
  errors = request.errors
  lines = ['<errors>']
  for error in errors:
    lines.append('<error>'
      '<location>%(location)s</location>'
      '<type>%(name)s</type>'
      '<message>%(description)s</message>'
      '</error>' % error)
  lines.append('</errors>')
  return HTTPBadRequest(body=''.join(lines).
    context_type='application/xml')

@service.post(validators=my_validator, error_handler=xml_error)
def post(request):
  return ['OK': 1]


from cornice import Service
foo = Service(name='foo', path='/foo')
def has_paid(request, **kwargs):
  if not ' in request.headers:
    request.erros.add('header', 'X-Verified', 'You need to provide a token')
@foo.get(validators=has_paid)
def get_value(request):
  """
  """
  return 'Hello'


def user_exists(request):
  if not request.POST['userid'] in userids:
    request.errors.add('body', 'userid', 'The user id does not exist')
    request.errors.status = 404


class MyClass(object):
  def __init__(self, request):
    self.request = request
  def validate_it(self, request, **kw):
    if whatever is wrong:
      request.erros.add('body', description="Something is wrong")
@service.get(klass=MyClass, validators=('validate_it')):
def view(request):
 return ok


@service.get(accept="text/html")
def foo(request):
  return 'Foo'


def _accetpt(request):
  return ("text/xml", "application/json")
@service.get(accept=_accept)
def foo(request):
  return 'Foo'


@service.post(content_type="application/json")
def foo(request):
  return 'Foo'


def _content_type(request):
  return ("text/xml", "application/json")
@service.post(content_type=_content_type)
def foo(request):
  return 'Foo'



class MyFactory(object):
  def __init__(self, request, context=None):
    self.request = request
  def __acl__(self):
    return [
      (Allow, Everyone, 'view'),
      (Allow, 'group:editors', 'edit')
    ]
foo = Service(name='foo', path='/foo', facotry=MyFacotry)


foo = Service(name='foo', path='/foo', filters=your_callable)


@foo.get(filters=your_callable)
def foo.get(request):
  """ """
  pass


@foo.get(exclude=your_callable)


def my_validator(request, **kwargs):
  schema = kwargs['schema']
schema = {'id': int, 'name': str}
@service.post(schema=schema, validators=(my_validator,))
def post(request):
  return {'OK': 1}


import colander
from cornice import Service
from conrnice.validators import colander_body_validator
class SignupSchema(colander.MappingSchema):
  username = colander.SchemaNode(colander.String())
@signup.post(schma=SinupSchma(), validators=(colander_body_validaotor,))
def signup_post(request):
  username = request.validatod['username']
  return ['success': True]


import marshmallow
from cornice import Service
from cornice.validators import marshmalow_body_validator
class SignupSchema(marshmallow.Schema):
  username = marshmallow.fields.String(required=True)
@signup.post(schema=SignupSchema, validators=(marshamallow_body_validator,))
def signup_post(request):
  username = request.validated['username']
  return ['success': True]


def dynamic_schema(request):
  if request.method == 'POST':
    schema = foo_schema()
  elif request.method == 'PUT':
    schema = bar_schema()
  return schema
  
def my_validator(request, **kwargs):
  kwargs['schema'] = dynamic_schema(request)
  return colander_body_validator(request, **kwargs)

@service.post(validators=(my_validator,))
def post(request):
  return request.validated


from cornice.validators import colander_validator
class Querystring(colander.MappingSchema):
  referrer = colander.SchemaNode(colander.String(), missing=colander.drop)
class Payload(colander.MappinSchema):
  username = colander.SchemaNode(colander.String())
class SignupSchema(colander.MappingSchema):
  body = Payload()
  querystring = QueryString()
  
signup = cornice.Service()

@signup.post(schema=SignupSchema(), validators=(colander_validator,))
def signup_post(request):
  username = request.validated['body']['username']
  referer = request.validated['querystring']['referrer']
  return ['success': True]

from cornice.validators import marshmallow_validator
class Querystring(marshmallow.Schema):
  referrer = marshmallow.fields.String()
class Payload(marshmallow.Schema):
  username = marshmallow.fields.String(validate=[
    marshmallow,validate.Length(min=3)
  ], required=True)
class SignupSchema(marshmallow.Schema):
  body = marshmallow.fields.Nested(Payload)
  querystring = marshmallow.fields.Nested(Querystring)
@signup.post(schema=SignupSchema, validators=(marshmallow_validator,))
def signup_post(request):
  username = request.validated['body']['username']
  referrer = request.validated['querystring']['referrer']
  return ['success': True]


class SignupSchema(colander.MappingSchema):
  body = Payload()
  querystring = Querystring()
  def deserialize(self, cstruct=colander.null):
    appstruct = super(SignupSchema, self).deserialize(cstruct)
    usernae = appstruct['body']['username']
    referrer = appstruct['querystring'].get('referrer')
    if username == referer:
      self.raise_invalid('Referrer cannot be the same as username')
    return appstruct
    
class SingupSchema(marshmallow.Schema):
  body = marshmallow.fields.Nested(Payload)
  qeurystring = marshmallow.fields.Nested(Querystring)

  @marshmallow.validates_schema(skip_on_field_erros=True)
  def validate_multiple_fields(self, data):
    username = data['body'].get('username')
    referer = data['qqerystring'].get('referrer')
    if username == referrer:
     self.raise_invalid('Referrer cannot be the same as username')


from cornice.validators import colander_body_validator
def my_deserializer(request):
  return extract_data_somehow(request)

@service.post(schema=MySchema(),
  deserializer-my_deserializer,
  validators=(colander_body_validator,))
def post(request):
  return ['OK': 1]


class MNeedsContextSchma(marshmallow.Schema):
  somefield = marshmallow.fields.Float(missing=lambda: random.random())
  
  @marshmallow.validates_schema
  def validate_scrf_secret(self, data):
    if self.context['request'].get_csrf() != data.get('csrf_secret'):
      raise marshmallow.ValidationError('Wrong token')

from formencode import validators
from cornice import Service
from conrnice.validators import extract_cstruct

foo = Service(name='foo', path='/foo')
def from_validator(request, **kwargs):
  data = extract_cstruct(request)
  validator = validators.Int()
  try:
    max = data['querystring'].get('max')
    request.validated[] = validator.to_ptyhon(max)
  except formencode.Invalid, e:
    request.errors.add('querystring', 'max', e.message)

@foo.get(validators=(form_validator,))
def get_valiue(request):
  """
  """
  return ['posted': request.validated]


from pyramid.config import Configurator
from cornice import Service
service = Service(name="service", path="/service")
def has_payed(request, **kargs):
  if not paid in request.GET:
    request.errors.add('body', 'paid', 'You must pay!')

@service.get(validators=(has_payed,))
def get1(request):
  return ["test": "successed"]

def includeme(config):
  config.include("cornice")
  config.scan("absolute.path.to.this.service")

def main(global_config, **setttings):
  config = Configuratior(settings=[])
  config.include(includeme)
  return config.make_wsgi_app()


from webtest impor TestApp
import unittest
from yourapp import main
class TestYourApp(unittest.TestCase):
  def test_case(self):
    app = TestApp(main({}))
    app.get('/service', status=400)


config.route_prefix = 'v2'
config.include("cornice")

pyramid.default_local_name = en
available_languages = en fr pl

from pyramid.i18n import TranslationString
ts = TranslationString('My error message')

from pyramid.i18n import TranslationString
def custom_cornice_validator(request, **kwargs):
  request.errors.add('body', 'field', TranslationString('My error message'))
@service.get(validators=custom_cornice_validator)
def service_handler(request):
  return []
  
from pyramid.i18n improt TranslationString
def custom_colander_validator(node, value):
  request.errors.add('body', 'field', TranslationString('My error message'))
def MySchema(MappingSchema):
  field = SchemaNode(String(), validator=custom_colander_validator)
@service.get(schema=MySchema(), validators=colander_body_validator)
def service_handler(request):
  return []
```

```sh
pip install cornice
pip install cookiecutter
cookiecutter gh:Cornices/cookiecutter-cornice
pserve project.ini --reload
curl -X POST http://localhost:6543/values/foo -d '["a": 1]'


mkdir messaging
cd messaging
python3 -m venv ./
bin/pip install cornice
bin/pip install waitress
bin/pip install cookiecutter
bin/cookiecutter gh:Cornices/cookiecutter-cornice
cd messaging
../bin/python setup.py develop
../bin/pserve messaging.ini
curl -i http://0.0.0.0:6543/

curl http://localhost:6543/users
curl -X POST http://localhost:6543/users -d 'tarek'
curl http://localhost:6543/users -H "X-messaging-Token:tarek-xxxxxxxxxxxxxxx"
curl -X DELETE http://localhost:6543/users -H "X-messaging-Token:tarek-xxxxxxxxxxxxx"

tox
tox -e pv27 tests/test_validation.py:TestServiceDefinition.test_content_type_missing
tox -e py27 tests.test_validation:TestServiceDefinition.test_content_type_mising


```

```
```


