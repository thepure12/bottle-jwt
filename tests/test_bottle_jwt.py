import unittest
import bottle
import src.bottle_jwt as bottle_jwt
from tests.bottle_tools import ServerTestBase
import json

class TestBottleJWT(ServerTestBase):
    def setUp(self) -> None:
        super().setUp()
        # self.app = bottle.Bottle(catchall=False)
        self.plugin = bottle_jwt.JWTPlugin("secret", debug=True)
        self.app.install(self.plugin)
        self.app.post("/token", callback=lambda: "")

    def test_getToken(self):
        res = self.urlopen("/token", "POST")
        dict_body = json.loads(res["body"])
        self.assertIn("token", dict_body)

    def test_getUser(self):
        res = self.urlopen("/token", "POST")
        dict_body = json.loads(res["body"])
        token = dict_body["token"]
        env = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        self.app.get("/user", callback=lambda: getattr(bottle.request, "user"))
        res = self.urlopen("/user", env=env)
        dict_body = json.loads(res["body"])
        self.assertIn("exp", dict_body)
    
    def test_getProtected(self):
        pass