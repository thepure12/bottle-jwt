from bottle import Bottle, request
from bottle_jwt import JWTPlugin

app = Bottle()

def auth():
    return { "permissions": "guest" }

def permiss():
    return True

plugin = JWTPlugin("changeme", auth, permissions_func=permiss)
app.install(plugin)

@app.route("/token", "POST")
def token():
    pass

@app.route("/user", "GET", permissions="guest")
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

app.run(debug=True, reloader=True)