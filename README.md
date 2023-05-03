# BottleJWT
JWT Plugin for Bottle. Adds functionality to protect routes via JWT and adds options for role based authentication.

## Installation
### Pip
```bash
python3 -m pip install bottle-jwt3
```
### Source
```bash
wget https://raw.githubusercontent.com/thepure12/bottle-jwt/main/src/bottle_jwt/bottle_jwt.py
```

## Usage
### Install Plugin
```python
from bottle import Bottle
from bottle_jwt import JWTPlugin

app = Bottle()
plugin = JWTPlugin(jwt_key="changeme")
app.install(plugin)
@app.route("/token", method="POST")
def token():
    pass
```

### Getting a Token
The default route for getting a token is "/token". Token routes only except POST requests and will pass post data as keyword arguments into the authentication (auth) function. The auth function creates the JWT payload which is encoded and returned to the requester.
```bash
$ curl localhost/token
{"message": "Method Not Allowed, use POST for authentication"}
$ curl -X POST localhost/token
{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJndWVzdCJdLCJleHAiOjE2ODMxMjcxODd9.5OkXOdRGbloRr4oI2pjeJoBqQvSaE-pkuaZoaAtKKSU"}
```

### Custom Auth
```python
def myAuth(**kwargs):
    token = {
        "exp": datetime.utcnow() + timedelta(minutes=5),
        "roles": ["user", "admin"]
    }
    return token

plugin = JWTPlugin(jwt_key="changeme", auth_func=myAuth)
```

Failed authenetication can be handled by raising an AuthFailed exception.

```python
from bottle_jwt import 
def myAuth(username, password):
    if myHash(username, password) != expected_hash:
        raise AuthFailed()
```

### Additional Token Paths
It might be useful to have multiple token paths to enable the use of multiple auth functions. Each token path is mapped to one auth function but one auth function may be mapped to multiple token paths.
```python
plugin = JWTPlugin(jwt_key="changeme")
plugin.addTokenPath("token2")
plugin.addTokenPath("token3", auth_func=myAuth)
```

### Protecting Routes
Protecting a route is handled via Bottle's route config. This simplest way to protect a route is to add a "roles" option to a route's config and set it to True. Roles can all be set to a list of strings (the roles required to access the route) or a callable that returns a boolean or list of strings.
```python
@route("/protected1", roles=True)
def protected():
    pass

@route("/protected2", roles=["user", "admin"])
def protected():
    pass

@route("/protected3", roles=myRolesFunc)
def protected():
    pass
```