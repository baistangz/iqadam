import os
import re

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from supabase import Client, create_client
from supabase_auth.errors import AuthApiError

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL")
CAPTCHA_SITE_KEY = os.getenv("CAPTCHA_SITE_KEY", "").strip()
CAPTCHA_REQUIRED = os.getenv("CAPTCHA_REQUIRED", "true").lower() == "true"
CAPTCHA_ENABLED = CAPTCHA_REQUIRED and bool(CAPTCHA_SITE_KEY)

EMAIL_REGEX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase credentials in environment variables.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="ORT Prep Backend")
# main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://iqadam.vercel.app",  # <--- YOUR VERCEL URL
        "http://localhost:5500",           # For local testing
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def normalize_email(value: str) -> str:
    return value.strip().lower()


def password_strength_error(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 128:
        return "Password is too long."
    if not re.search(r"[a-z]", password):
        return "Password must include a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must include an uppercase letter."
    if not re.search(r"\d", password):
        return "Password must include a number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include a special character."
    if re.search(r"\s", password):
        return "Password cannot contain spaces."
    return None


def validate_captcha_token(token: str | None) -> str | None:
    if token is None:
        if CAPTCHA_ENABLED:
            raise ValueError("Captcha verification is required.")
        return None

    normalized_token = token.strip()
    if CAPTCHA_ENABLED and not normalized_token:
        raise ValueError("Captcha verification is required.")
    if normalized_token and len(normalized_token) > 2048:
        raise ValueError("Invalid captcha token.")
    return normalized_token or None


def build_auth_http_error(error: AuthApiError, action: str) -> HTTPException:
    code = (error.code or "").lower()

    if code in {"invalid_credentials"}:
        return HTTPException(status_code=401, detail="Invalid email or password.")
    if code in {"email_not_confirmed"}:
        return HTTPException(
            status_code=403,
            detail="Email is not confirmed. Please confirm your email first.",
        )
    if code in {"email_address_invalid"}:
        return HTTPException(status_code=422, detail="Invalid email format.")
    if code in {"captcha_failed"}:
        return HTTPException(
            status_code=403,
            detail="Captcha verification failed. Please try again.",
        )
    if code in {"over_request_rate_limit", "over_email_send_rate_limit"}:
        return HTTPException(
            status_code=429,
            detail="Too many requests. Please try again in a moment.",
        )
    if action == "register" and code in {"email_exists", "user_already_exists"}:
        return HTTPException(
            status_code=409,
            detail="This email is already registered. Please log in instead.",
        )

    return HTTPException(status_code=error.status, detail=error.message)


class QuestionOptions(BaseModel):
    A: str
    B: str
    C: str
    D: str


class QuestionInsert(BaseModel):
    subject: str
    question: str
    options: QuestionOptions


class AuthEmailRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = normalize_email(value)
        if not email:
            raise ValueError("Email is required.")
        if len(email) > 254:
            raise ValueError("Email is too long.")
        if not EMAIL_REGEX.fullmatch(email):
            raise ValueError("Invalid email format.")
        return email


class LoginCredentials(AuthEmailRequest):
    password: str
    captcha_token: str | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Password is required.")
        if len(value) > 128:
            raise ValueError("Password is too long.")
        return value

    @field_validator("captcha_token")
    @classmethod
    def validate_captcha(cls, value: str | None) -> str | None:
        return validate_captcha_token(value)


class RegisterCredentials(AuthEmailRequest):
    password: str
    captcha_token: str | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        error_message = password_strength_error(value)
        if error_message:
            raise ValueError(error_message)
        return value

    @field_validator("captcha_token")
    @classmethod
    def validate_captcha(cls, value: str | None) -> str | None:
        return validate_captcha_token(value)


class ResendConfirmationRequest(AuthEmailRequest):
    pass


def serialize_user(user) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def serialize_session(session) -> dict:
    return {
        "access_token": session.access_token,
        "refresh_token": session.refresh_token,
        "expires_in": session.expires_in,
        "token_type": session.token_type,
    }


@app.post("/api/auth/register")
async def register_user(credentials: RegisterCredentials):
    try:
        signup_payload = {
            "email": credentials.email,
            "password": credentials.password,
        }
        signup_options: dict[str, str] = {}
        if FRONTEND_URL:
            signup_options["email_redirect_to"] = FRONTEND_URL
        if credentials.captcha_token:
            signup_options["captcha_token"] = credentials.captcha_token
        if signup_options:
            signup_payload["options"] = signup_options

        auth_response = supabase.auth.sign_up(signup_payload)
        return {
            "message": "Registration request sent.",
            "user": serialize_user(auth_response.user) if auth_response.user else None,
            "session": (
                serialize_session(auth_response.session)
                if auth_response.session
                else None
            ),
            "needs_email_confirmation": auth_response.session is None,
            "email_redirect_to": FRONTEND_URL,
        }
    except AuthApiError as e:
        raise build_auth_http_error(e, action="register")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/api/auth/login")
async def login_user(credentials: LoginCredentials):
    try:
        signin_payload: dict[str, object] = {
            "email": credentials.email,
            "password": credentials.password,
        }
        if credentials.captcha_token:
            signin_payload["options"] = {"captcha_token": credentials.captcha_token}

        auth_response = supabase.auth.sign_in_with_password(signin_payload)
        if not auth_response.session or not auth_response.user:
            raise HTTPException(status_code=401, detail="Invalid login response.")

        user = auth_response.user
        if user.email and not (user.email_confirmed_at or user.confirmed_at):
            try:
                supabase.auth.sign_out()
            except Exception:
                pass
            raise HTTPException(
                status_code=403,
                detail="Email is not confirmed. Please confirm your email first.",
            )

        return {
            "message": "Login successful.",
            "user": serialize_user(user),
            "session": serialize_session(auth_response.session),
        }
    except AuthApiError as e:
        raise build_auth_http_error(e, action="login")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@app.get("/api/auth/config")
async def get_auth_config():
    return {
        "captcha_enabled": CAPTCHA_ENABLED,
        "captcha_site_key": CAPTCHA_SITE_KEY if CAPTCHA_ENABLED else None,
    }


@app.post("/api/auth/resend-confirmation")
async def resend_confirmation_email(payload: ResendConfirmationRequest):
    try:
        resend_payload = {
            "type": "signup",
            "email": payload.email,
        }
        if FRONTEND_URL:
            resend_payload["options"] = {"email_redirect_to": FRONTEND_URL}

        supabase.auth.resend(resend_payload)
        return {"message": "Confirmation email sent if the account exists."}
    except AuthApiError as e:
        if (e.code or "").lower() == "user_not_found":
            return {"message": "Confirmation email sent if the account exists."}
        raise build_auth_http_error(e, action="resend_confirmation")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not resend email: {str(e)}")


@app.get("/api/auth/me")
async def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing access token.")

    try:
        response = supabase.auth.get_user(token)
        if not response or not response.user:
            raise HTTPException(status_code=401, detail="Invalid token.")
        user = response.user
        if user.email and not (user.email_confirmed_at or user.confirmed_at):
            raise HTTPException(
                status_code=403,
                detail="Email is not confirmed. Please confirm your email first.",
            )
        return {"user": serialize_user(user)}
    except AuthApiError as e:
        raise build_auth_http_error(e, action="me")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token validation failed: {str(e)}")


@app.post("/api/questions/bulk-upload")
async def upload_questions(questions: list[QuestionInsert]):
    try:
        data_to_insert = [
            {
                "subject": q.subject,
                "question_text": q.question,
                "options": q.options.model_dump(),
            }
            for q in questions
        ]

        response = supabase.table("questions").insert(data_to_insert).execute()
        return {
            "status": "success",
            "message": f"Successfully inserted {len(response.data)} questions.",
            "data": response.data,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/api/questions")
async def get_questions(
    mock_exam: int | None = Query(default=None, ge=16, le=22)
):
    if mock_exam is not None and mock_exam != 19:
        return []
    response = supabase.table("questions").select("*").execute()
    return response.data
