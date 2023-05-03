import bottle
import jwt
from datetime import datetime, timedelta

class JWTError(bottle.HTTPResponse):

    def __init__(self, message='', status=500):
        super().__init__({"message": message}, status, headers={"Content-Type": "application/json"})

class AuthHeaderMissing(JWTError):

     def __init__(self) -> None:
        super().__init__("Authorization header is expected", 400)

class InvalidAuthScheme(JWTError):
    
     def __init__(self) -> None:
        super().__init__("Authorization header must start with Bearer", 400)

class TokenNotFound(JWTError):

     def __init__(self) -> None:
        super().__init__("Token not found", 400)

class InvalidHeader(JWTError):

     def __init__(self) -> None:
        super().__init__("Authorization header must be Bearer + ' ' + <token>", 400)

class InvalidAlgorithm(JWTError):

     def __init__(self) -> None:
        super().__init__("The specified alg value is not allowed", 400)

class MethodNotAllowed(JWTError):

    def __init__(self) -> None:
        super().__init__("Method Not Allowed, use POST for authentication", 405)

class AuthFailed(JWTError):

     def __init__(self, message="Authentication failed",) -> None:
        super().__init__(message, 401)

class InvalidAudience(JWTError):

     def __init__(self) -> None:
        super().__init__("You do not have permission to access this content", 403)

class ExpiredSignature(JWTError):

     def __init__(self) -> None:
        super().__init__("Signature has expired", 401)

def authFunc():
    return {
        "exp": datetime.utcnow() + timedelta(days=30)
    }

class JWTPlugin():
    name = 'jwt'
    api = 2

    def __init__(self, jwt_key, auth_func=authFunc, token_path="token", alg="HS256", fail_redirect="", debug=False) -> None:
        self.jwt_key = jwt_key
        self.token_paths = { token_path: auth_func }
        self.alg = alg
        self.fail_redirect = fail_redirect
        self.debug = debug

    def addTokenPath(self, token_path, auth_func=None):
        if not auth_func:
            auth_func = lambda: {
                "exp": datetime.utcnow() + timedelta(days=30)
            }
        self.token_paths[token_path] = auth_func

    def handleException(self, exception):
        if self.fail_redirect:
            bottle.redirect(self.fail_redirect)
        else:
            raise exception

    def getTokenFromHeader(self):
        auth = bottle.request.headers.get('Authorization', None)
        if not auth:
            self.handleException(AuthHeaderMissing())

        parts = auth.split() # ["Bearer", "xxxxx.yyyyy.zzzzz"] 

        if parts[0].lower() != 'bearer':
            raise InvalidAuthScheme()
        elif len(parts) == 1:
            raise TokenNotFound()
        elif len(parts) > 2:
            raise InvalidHeader()

        return parts[1] # "xxxxx.yyyyy.zzzzz"

    def createToken(self, path, **kwargs):
        if self.debug:
            print(f"bottle_jwt: Creating token for path '{path}'")
        payload = self.token_paths[path](**kwargs)
        if payload:
            # If auth_func was succcessful, encode the payload
            # Figure out custom message for failed auth
            encoded = jwt.encode(payload, self.jwt_key, algorithm=self.alg)
            return encoded
        else:
            raise AuthFailed()

    def handleTokenPath(self, path, route, **kwargs):
        if route.method == "GET":
            raise MethodNotAllowed()
        elif route.method == "POST":
            req_json = bottle.request.json if bottle.request.json else {}
            token = self.createToken(path, **req_json, **kwargs)
            if token:
                return {"token": token}
            else:
                raise AuthFailed()

    def decodeToken(self):
        if self.debug:
            print(f"bottle_jwt: Decoding token")
        try:
            token = self.getTokenFromHeader()
            decoded = jwt.decode(token, self.jwt_key, algorithms=[self.alg])
            bottle.request.__setattr__("user", decoded)
            return decoded
        except jwt.ExpiredSignatureError:
            bottle.request.__setattr__("user", None)
            return ExpiredSignature()
        except jwt.PyJWTError as e:
            bottle.request.__setattr__("user", None)
            return JWTError(message=str(e), status=400)
        except Exception as e:
            bottle.request.__setattr__("user", None)
            return e

    def checkRoles(self, roles, route, decoded):
        if self.debug:
            print(f"bottle_jwt: Checking route config for roles: {route.config}")
        if isinstance(decoded, Exception):
            # If decoding the token returned and exceptions
                raise decoded
        elif callable(roles):
            # If roles is a function
            roles = roles()
        if isinstance(roles, bool) and decoded:
            # Token required, but no role required
            return
        roles = bottle.makelist(roles)
        user_roles = bottle.makelist(decoded.get("roles", True))
        if set(roles).isdisjoint(user_roles):
            # If user does not have required role
            raise InvalidAudience()

    def apply(self, fn, route: bottle.Route):
        def _jwt(*args, **kwargs):
            path = route.rule.replace("/", "")
            roles = route.config.get("roles", None)
            if self.debug:
                print(f"bottle_jwt: Checking if '{path}' is token path.")
            # Checking for user
            decoded = self.decodeToken()
            if path in self.token_paths:
                return self.handleTokenPath(path, route, **kwargs)
            else:
                # Checking for roles
                if roles:
                    self.checkRoles(roles, route, decoded)
            return fn(*args, **kwargs)
        return _jwt