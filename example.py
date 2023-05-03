from bottle import Bottle, request
from src.bottle_jwt import JWTPlugin, AuthFailed
from datetime import datetime, timedelta

app = Bottle()

def auth():
    return { "roles": ["guest"], "exp": datetime.utcnow() + timedelta(minutes=5) }

def fail_auth(**kwargs):
    raise AuthFailed() 

plugin = JWTPlugin("changeme", auth_func=auth, debug=True)
plugin.addTokenPath("token2", auth_func=auth)
plugin.addTokenPath("token_fail", auth_func=fail_auth)
app.install(plugin)

@app.route("/token", method=["GET", "POST"])
def token():
    pass

@app.route("/token2", method=["GET", "POST"])
def token2():
    pass

@app.route("/token_fail", method=["GET", "POST"])
def token2():
    pass

@app.route("/user", "GET")
def user():
    return {"user": request.user}

@app.route("/callable_roles/list", roles=lambda: ["guest", "user"])
def gen_list():
    return {"msg": "Generated list of roles"}

@app.route("/callable_roles/bool", roles=lambda: True)
def gen_bool():
    return {"msg": "Generated a boolean"}

@app.route("/token_protected", roles=True)
def permiss_func():
    return {"msg": "Used the check roles function"}

app.run( host="localhost", debug=True, reloader=True)