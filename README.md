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
```

```
```


