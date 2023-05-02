from bottle import Bottle, request
from src.bottle_jwt import JWTPlugin
from datetime import datetime, timedelta

app = Bottle()

def auth():
    return { "roles": ["guest"], "exp": datetime.utcnow() + timedelta(minutes=5) }

plugin = JWTPlugin("changeme", debug=True)
plugin.addTokenPath("app_token")
app.install(plugin)

@app.route("/token", method=["GET", "POST"])
def token():
    pass

@app.route("/app_token", method=["GET", "POST"])
def appToken():
    pass

@app.route("/user", "GET", roles=True)
def user():
    return {"user": request.user}

@app.route("/gen_list", permissions=lambda: ["guest", "user"])
def gen_list():
    return {"msg": "Generated list of permissions"}

@app.route("/gen_bool", permissions=lambda: True)
def gen_bool():
    return {"msg": "Generated a boolean"}

@app.route("/permiss_func", permissions=True)
def permiss_func():
    return {"msg": "Used the permssions function"}

app.run( host="0.0.0.0", debug=True, reloader=True)