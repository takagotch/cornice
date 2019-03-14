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

```

```
```

```
```


