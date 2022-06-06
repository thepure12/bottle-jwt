from . import bottle
import jwt

class JWTPlugin():
    name = 'jwt'
    api = 2

    def __init__(self, jwt_key, auth_func, token_path="token", debug=False) -> None:
        self.jwt_key = jwt_key
        self.auth_func = auth_func
        self.token_path = token_path
        self.debug = debug

    def jwt_token_from_header(self):
        auth = bottle.request.headers.get('Authorization', None)
        if not auth:
            raise Exception(
                {'message': 'authorization_header_missing', 'description': 'Authorization header is expected'})

        parts = auth.split()

        if parts[0].lower() != 'bearer':
            raise Exception(
                {'message': 'invalid_header', 'description': 'Authorization header must start with Bearer'})
        elif len(parts) == 1:
            raise Exception(
                {'message': 'invalid_header', 'description': 'Token not found'})
        elif len(parts) > 2:
            raise Exception(
                {'message': 'invalid_header', 'description': 'Authorization header must be Bearer + \\s + token'})

        return parts[1]

    def getDecodedToken(self):
        token = self.jwt_token_from_header()
        try:
            return jwt.decode(token, self.jwt_key, algorithms=["HS256"])
        except:
            return jwt.decode(token, self.jwt_key)

    def getToken(self, **kwargs):
        if self.debug:
            print("bottle_jwt: Getting token.")
        payload = self.auth_func(**kwargs)
        if payload:
            if bottle.response.status_code != 200:
                return payload
            encoded = jwt.encode(payload, self.jwt_key, algorithm="HS256")
            try:
                return jwt.encode(payload, self.jwt_key, algorithm="HS256").decode("utf-8")
            except:
                return encoded
        else:
            return None

    def apply(self, fn, route: bottle.Route):
        def _jwt(*args, **kwargs):
            path = route.rule.replace("/", "")
            req_permissions = route.config.get("permissions", None)
            if self.debug:
                print(f"bottle_jwt: Checking if '{path}' is token path.")
            if path == self.token_path:
                if route.method == "GET":
                    bottle.response.status = 405
                    return {
                        "message": "Method Not Allowed, use POST for authentication"
                    }
                elif route.method == "POST":
                    try:
                        token = self.getToken(**bottle.request.json, **kwargs)
                        if token:
                            return {"token": token}
                        else:
                            bottle.response.status = 401
                            return {"message": "authentication failed"}
                    except Exception as e:
                        bottle.response.status = 500
                        return {"message": e}
            else:
                # Checking for user
                try:
                    decoded = self.getDecodedToken()
                    bottle.request.__setattr__("user", decoded)
                except Exception as e:
                    bottle.request.__setattr__("user", None)
                    if req_permissions:
                        bottle.response.status = 400
                        return e.args[0]
                # Checking for permssions
                if req_permissions:
                    if self.debug:
                        print(f"bottle_jwt: Checking route config for permissions: {route.config}")
                    try:
                        # Is permissions a functions
                        if callable(req_permissions):
                            req_permissions = req_permissions()
                        req_permissions = bottle.makelist(req_permissions)
                        user_permissions = bottle.makelist(decoded["permissions"])
                        # Does user have sufficient permissions
                        if set(req_permissions).isdisjoint(user_permissions):
                            raise jwt.InvalidAudienceError
                    except jwt.InvalidAudienceError:
                        bottle.response.status = 401
                        return { 
                            "message": "insufficent_permissions",
                            "description": "you do not have permission to access this content"
                        }
                    except jwt.ExpiredSignatureError:
                        bottle.response.status = 401
                        return {
                            'message': 'token_expired',
                            'description': 'token is expired'
                        }
            return fn(*args, **kwargs)
        return _jwt