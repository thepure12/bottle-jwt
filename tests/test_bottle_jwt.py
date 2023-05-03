import bottle
import src.bottle_jwt as bottle_jwt
from tests.bottle_tools import ServerTestBase
import json
from datetime import datetime, timedelta


class TestBottleJWT(ServerTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.plugin = bottle_jwt.JWTPlugin("secret", debug=True)
        self.app.install(self.plugin)
        self.app.post("/token", callback=lambda: "")

    def test_getToken(self):
        res = self.urlopen("/token", "POST")
        dict_body = json.loads(res["body"])
        self.assertIn("token", dict_body)

    def test_authFailed(self):
        def auth():
            raise bottle_jwt.AuthFailed()
        self.plugin.token_paths["token"] = auth
        self.assertStatus(401, "/token", method="POST")

    def test_getUser(self):
        self.app.get("/user", callback=lambda: getattr(bottle.request, "user"))
        env = {"HTTP_AUTHORIZATION": f"Bearer {self.getToken()}"}
        res = self.urlopen("/user", env=env)
        dict_body = json.loads(res["body"])
        self.assertIn("exp", dict_body)

    def test_protected(self):
        self.createProtected()
        self.assertBody("protected", "/protected", env=self.env)
        # Protected without roles, but user has roles
        self.plugin.token_paths["token"] = lambda: {"roles": ["admin"]}
        self.assertBody("protected", "/protected", env=self.env)

    def test_protectedByRole(self):
        self.createProtected("admin")
        self.plugin.token_paths["token"] = lambda: {"roles": ["admin"]}
        self.assertBody("protected", "/protected", env=self.env)

    def test_protectedByRoles(self):
        self.createProtected(["user", "admin"])
        self.plugin.token_paths["token"] = lambda: {"roles": ["admin"]}
        self.assertBody("protected", "/protected", env=self.env)
        self.plugin.token_paths["token"] = lambda: {"roles": ["user"]}
        self.assertBody("protected", "/protected", env=self.env)

    def test_callableRoles(self):
        roles = lambda: True
        self.createProtected(roles)
        self.assertBody("protected", "/protected", env=self.env)

    def test_authorizationMissing(self):
        self.createProtected()
        self.assertStatus(400, "/protected")

    def test_invalidAudience(self):
        self.createProtected("admin")
        self.assertStatus(403, "/protected", env=self.env)

    def test_expiredToken(self):
        self.createProtected()
        self.plugin.token_paths["token"] = lambda: {
            "exp": datetime.utcnow() - timedelta(days=1)
        }
        self.assertStatus(401, "/protected", env=self.env)

    # Helper functions
    def createProtected(self, roles=True):
        self.app.get("/protected", callback=lambda: "protected", roles=roles)

    def getToken(self) -> str:
        res = self.urlopen("/token", "POST")
        dict_body = json.loads(res["body"])
        return dict_body["token"]

    @property
    def env(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.getToken()}"}
