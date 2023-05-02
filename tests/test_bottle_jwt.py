import unittest
import bottle
import src.bottle_jwt as bottle_jwt


class TestBottleJWT(unittest.TestCase):
    def setUp(self) -> None:
        self.app = bottle.Bottle(catchall=False)
        self.plugin = bottle_jwt.JWTPlugin("secret")
        self.app.install(self.plugin)

    def tearDown(self) -> None:
        return super().tearDown()

    def test_getToken(self):
        self.app.post("/token", callback=lambda: "")
        res = self._request('/token', 'POST')
        self.assertIn("token", res.json())

    def _request(self, path, method="GET"):
        return self.app(
            {"PATH_INFO": path, "REQUEST_METHOD": method}, lambda x, y: None
        )
