from fastapi import FastAPI, Depends, HTTPException, Request, Response, status, Form
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel
import uvicorn
import logging
import secrets


# CORS Configuration (You may need to adjust origins based on your requirements)
origins = [
    "127.0.0.1",
]

ALLOWED_METHODS = ["GET", "POST"]


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=ALLOWED_METHODS,
    allow_headers=["*"],
)

# Security Configuration
# Replace these with your actual Keycloak OIDC settings.
keycloak_url = "https://your-keycloak-server/auth/realms/your-realm"
client_id = "your-client-id"
client_secret = "your-client-secret"


# Session store
sessions = {}


# Rate limiting middleware
limiter = Limiter(key_func=get_remote_address)

app.state.limiter = limiter

logger = logging.getLogger("app")
logger.setLevel(logging.DEBUG)




@app.middleware("http")
async def check_ip(request: Request, call_next):
    response = await call_next(request)
    ip = str(request.client.host)
    if ip not in origins:
        data = {'message': f'IP {ip} is not allowed to access this resource.'}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
    return response

@app.middleware("http")
async def check_request_method(request: Request, call_next):
    response = await call_next(request)
    method = request.method
    if method not in ALLOWED_METHODS:
        data = {'message': f'Not allowed method'}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
    return response

#@app.middleware("http")
#async def check_incoming_header(request: Request, call_next):
#    response = await call_next(request)
#    xframe = request.headers.get("X-Frame-Options")
#    xcontent = request.headers.get("X-Content-Type-Options")
#    xss = request.headers.get("X-XSS-Protection")
#    if xframe != "DENY" or xcontent != "nosniff" or xss != "1; mode=block":
#        data = {'message': f'Header not allowed'}
#        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
#    return response

# Security headers middleware
@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Type"] = "application/json"
    return response


class CustomInput(BaseModel):
    sub: str 
    


class Token(BaseModel):
    access_token: str
    token_type: str


class LoginData(BaseModel):
    username: str
    password: str

def generate_csrf_token():
    return secrets.token_urlsafe(32)

class UserSession:
    def __init__(self, username, csrf_token):
        self.username = username
        self.csrf_token = csrf_token

def create_user_session(username: str):
    if username in sessions:
        # If user already has a session, remove it (only allow one session per user)
        del sessions[username]
    sessions[username] = {}
    sessions[username]["csrf_token"] = generate_csrf_token()
    return(sessions[username]["csrf_token"])


# Dependency for user validation
async def user_validation(login_data: LoginData):
    username = login_data.username 
    password = login_data.password
    if username == "fero" and password == "heslo":
        session_csrf = create_user_session(username = username)
        return {"sub": session_csrf}
    raise HTTPException(status_code=400, detail="Incorrect username or password")

# Check user 
async def session_validation(request: Request):
    username = "fero"
    csrf_token = request.headers.get("X-CSRF-TOKEN")
    print(sessions)
    if not username or username not in sessions:
        raise HTTPException(status_code=403, detail="No active session")
    if csrf_token != sessions.get(username).get("csrf_token"):
        raise HTTPException(status_code=403, detail="Wrong CSRF token")
    return sessions[username]

@app.post("/login")
async def login(request: Request, user = Depends(user_validation)):
    # Generate CSRF token and set it in a cookie (as before)
    # Replace with actual CSRF token generation logic
    csrf_token = user["sub"]
    response = Response()
    response.set_cookie(key="csrf_token", value=csrf_token, httponly=True)
    # Additional login logic if necessary

    return response


@app.get("/logout", tags=["Authentication"])
async def logout(request: Request):
    # Add logout logic here if needed
    return JSONResponse(content = {"response": "logged out"}, status_code=200)


@app.get("/process1", tags=["Process"])
@limiter.limit("1/second")
async def process1(request: Request, user = Depends(session_validation)):
    # Add your logic here for /process1
    return JSONResponse(content = {"username": user}, status_code=200)


@app.get("/process2", tags=["Process"])
@limiter.limit("2/second")
async def process2(request: Request):
    # Add your logic here for /process2
    return JSONResponse(content = {"response": "process2"}, status_code=200)



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)