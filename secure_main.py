from fastapi import FastAPI, Request, Form, Depends, HTTPException, Response, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from database import get_db, engine # Add engine import
from models import User, Customer, Base, PasswordResetToken, PasswordHistory # Assuming these models are defined
from passlib.hash import pbkdf2_sha256
import secrets
import os
from sqlalchemy import and_
import hashlib
from datetime import datetime, timedelta
import config
import html  # Add this import for HTML escaping
from email_utils import send_reset_code

# We will NOT import pickle, subprocess here as they are sources of vulnerabilities

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Configure Jinja2 to auto-escape HTML
templates.env.autoescape = True

# In-memory storage for secure sessions (for demo purposes)
# In a real app, use a proper server-side session store or JWTs
active_sessions = set() # Stores session tokens

# In-memory storage for reset codes (for demo purposes)
reset_codes = {}  # {email: {"code": code, "expires": expiration_time}}

# Add this at the top with other global variables
reset_tokens = {}  # {token: email}

# --- SECURE ENDPOINTS ---

@app.get("/secure/")
def secure_home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request, "route_prefix": "/secure"})

@app.post("/secure/register")
def register_secure(request: Request, username: str = Form(...), password: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    # Check password complexity
    if len(password) < config.PASSWORD_MIN_LENGTH:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters long",
            "route_prefix": "/secure"
        })
    
    if config.PASSWORD_REQUIRE_UPPER and not any(c.isupper() for c in password):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password must contain at least one uppercase letter",
            "route_prefix": "/secure"
        })
    
    if config.PASSWORD_REQUIRE_LOWER and not any(c.islower() for c in password):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password must contain at least one lowercase letter",
            "route_prefix": "/secure"
        })
    
    if config.PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password must contain at least one digit",
            "route_prefix": "/secure"
        })
    
    if config.PASSWORD_REQUIRE_SPECIAL and not any(c in config.SPECIAL_CHARS for c in password):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password must contain at least one special character",
            "route_prefix": "/secure"
        })
    
    # Check if password is in common passwords list
    if password.lower() in [p.lower() for p in config.COMMON_PASSWORDS]:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password is too common. Please choose a stronger password",
            "route_prefix": "/secure"
        })

    # Check if user already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Email already registered",
            "route_prefix": "/secure"
        })
    
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Username already taken",
            "route_prefix": "/secure"
        })

    # Create new user
    hashed_password = pbkdf2_sha256.hash(password)
    new_user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        salt="pbkdf2_managed"
    )
    
    # Add to password history
    password_history = PasswordHistory(
        user=new_user,
        hashed_password=hashed_password
    )
    
    db.add(new_user)
    db.add(password_history)
    db.commit()
    db.refresh(new_user)

    return templates.TemplateResponse("register.html", {
        "request": request,
        "message": "Registration successful! You can now log in.",
        "route_prefix": "/secure"
    })

@app.get("/secure/register", response_class=HTMLResponse)
def register_form_secure(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "route_prefix": "/secure"})

@app.get("/secure/login", response_class=HTMLResponse)
def login_form_secure(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "route_prefix": "/secure"})

@app.post("/secure/login")
def login_secure(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()

    if user and pbkdf2_sha256.verify(password, user.hashed_password):
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        active_sessions.add(session_token)
        
        response = RedirectResponse(url="/secure/add-customer", status_code=303)
        response.set_cookie(key="session_token", value=session_token, httponly=True, secure=False)
        return response
    else:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials",
            "route_prefix": "/secure"
        })

# Helper function for secure authentication check
def require_secure_login(request: Request, session_token: str = Cookie(None)):
    if session_token not in active_sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return True # Or return the user object if needed

@app.get("/secure/add-customer", response_class=HTMLResponse)
def customer_form_secure(request: Request, authenticated: bool = Depends(require_secure_login)):
    # Authentication check is done by the dependency
    return templates.TemplateResponse("add_customer.html", {"request": request, "route_prefix": "/secure"})

@app.post("/secure/add-customer")
def add_customer_secure(request: Request, name: str = Form(...), email: str = Form(...),
                 phone: str = Form(...), address: str = Form(...),
                 db: Session = Depends(get_db), authenticated: bool = Depends(require_secure_login)):
    # Authentication check is done by the dependency

    # Check if customer email already exists using ORM
    existing_customer = db.query(Customer).filter(Customer.email == email).first()
    if existing_customer:
         return templates.TemplateResponse("add_customer.html", {
             "request": request,
             "error": "Customer with this email already exists.",
             "route_prefix": "/secure"
         })

    # Create a new Customer instance using the ORM model
    new_customer = Customer(name=name, email=email, phone=phone, address=address)

    # Add and commit the new customer using ORM (secure)
    db.add(new_customer)
    db.commit()
    db.refresh(new_customer) # Refresh to get the generated ID

    # Escape HTML in the name before displaying it
    safe_name = html.escape(name)
    
    # Return success message with escaped HTML
    return templates.TemplateResponse("add_customer.html", {
        "request": request,
        "message": f"Customer '{safe_name}' added successfully!",
        "route_prefix": "/secure"
    })

# Add a route to display success message after redirect
@app.get("/secure/add-customer")
def customer_form_with_message_secure(request: Request, db: Session = Depends(get_db), authenticated: bool = Depends(require_secure_login), success_message: str = Cookie(None)):
    # Check for success message cookie and display it once
    response = templates.TemplateResponse("add_customer.html", {"request": request, "message": success_message, "route_prefix": "/secure"})
    if success_message:
        response.delete_cookie(key="success_message")
    return response

@app.get("/secure/forgot-password", response_class=HTMLResponse)
def forgot_password_form_secure(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "route_prefix": "/secure"})

@app.post("/secure/forgot-password")
def forgot_password_request_secure(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    print(f"[DEBUG] Forgot password request for email: {email}")
    # Find the user by email using ORM
    user = db.query(User).filter(User.email == email).first()

    if user:
        # Generate a SHA-1 token
        token_string = hashlib.sha1(f"{user.email}{datetime.now().timestamp()}".encode()).hexdigest()
        print(f"[DEBUG] Generated SHA1 code: {token_string}")
        
        # Store the code with expiration time (5 minutes)
        reset_codes[email] = {
            "code": token_string,
            "expires": datetime.now() + timedelta(minutes=5)
        }
        print(f"[DEBUG] Stored reset code for {email}")
        
        # Send the reset code via email
        if send_reset_code(email, token_string):
            print(f"[SECURE] Reset code sent to {email}: {token_string}")
            return templates.TemplateResponse("enter_code.html", {
                "request": request,
                "email": email,
                "route_prefix": "/secure",
                "message": "Reset code has been sent to your email."
            })
        else:
            print(f"[DEBUG] Failed to send reset code to {email}")
            return templates.TemplateResponse("forgot_password.html", {
                "request": request,
                "error": "Failed to send reset code. Please try again.",
                "route_prefix": "/secure"
            })
    else:
        print(f"[DEBUG] No user found for email: {email}")
        return templates.TemplateResponse("forgot_password.html", {
            "request": request,
            "message": "If a user with that email exists, a reset code has been sent.",
            "route_prefix": "/secure"
        })

@app.get("/secure/enter-code", response_class=HTMLResponse)
def enter_code_form_secure(request: Request, email: str = ""):
    return templates.TemplateResponse("enter_code.html", {
        "request": request,
        "email": email,
        "route_prefix": "/secure"
    })

@app.post("/secure/enter-code")
def enter_code_secure(request: Request, email: str = Form(...), code: str = Form(...), db: Session = Depends(get_db)):
    print(f"[DEBUG] Enter code attempt for email: {email}, code: {code}")
    print(f"[DEBUG] Stored codes: {reset_codes}")
    
    # Check if code exists and is not expired
    if email not in reset_codes:
        print(f"[DEBUG] No reset code found for {email}")
        return templates.TemplateResponse("enter_code.html", {
            "request": request,
            "email": email,
            "error": "No reset code found. Please request a new one.",
            "route_prefix": "/secure"
        })
    
    stored_code = reset_codes[email]
    if datetime.now() > stored_code["expires"]:
        print(f"[DEBUG] Reset code expired for {email}")
        del reset_codes[email]  # Remove expired code
        return templates.TemplateResponse("enter_code.html", {
            "request": request,
            "email": email,
            "error": "Reset code has expired. Please request a new one.",
            "route_prefix": "/secure"
        })
    
    # Validate the code
    if code != stored_code["code"]:
        print(f"[DEBUG] Invalid code for {email}. Expected: {stored_code['code']}, Got: {code}")
        return templates.TemplateResponse("enter_code.html", {
            "request": request,
            "email": email,
            "error": "Invalid code. Please try again.",
            "route_prefix": "/secure"
        })
    
    # Code is valid, generate a new token for password reset
    token = secrets.token_urlsafe(16)
    reset_tokens[token] = email
    print(f"[DEBUG] Generated new token for {email}: {token}")
    
    # Redirect to reset password page with the new token
    redirect_url = f"/secure/reset-password/{token}"
    print(f"[DEBUG] Redirecting to: {redirect_url}")
    return RedirectResponse(url=redirect_url, status_code=303)

@app.get("/secure/reset-password/{token}", response_class=HTMLResponse)
def reset_password_form_secure(request: Request, token: str):
    print(f"[DEBUG] Reset password form request for token: {token}")
    print(f"[DEBUG] Available tokens: {reset_tokens}")
    
    if token not in reset_tokens:
        print(f"[DEBUG] Invalid token: {token}")
        return templates.TemplateResponse("forgot_password.html", {
            "request": request,
            "error": "Invalid or expired token. Please request a new reset code.",
            "route_prefix": "/secure"
        })
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "token": token,
        "route_prefix": "/secure"
    })

@app.post("/secure/reset-password/{token}")
def reset_password_secure(request: Request, token: str, new_password: str = Form(...), confirm_password: str = Form(...), db: Session = Depends(get_db)):
    if token not in reset_tokens:
        return templates.TemplateResponse("forgot_password.html", {
            "request": request,
            "error": "Invalid or expired token. Please request a new reset code.",
            "route_prefix": "/secure"
        })

    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "token": token,
            "error": "Passwords do not match.",
            "route_prefix": "/secure"
        })

    try:
        # Get email from token
        email = reset_tokens[token]
        
        # Find user by email
        user = db.query(User).filter(User.email == email).first()
        if user:
            # Update the password
            user.hashed_password = pbkdf2_sha256.hash(new_password)
            db.commit()
            
            # Clean up tokens
            del reset_tokens[token]
            if email in reset_codes:
                del reset_codes[email]
                
            return templates.TemplateResponse("login.html", {
                "request": request,
                "message": "Password changed successfully. Please log in.",
                "route_prefix": "/secure"
            })
        else:
            return templates.TemplateResponse("change_password.html", {
                "request": request,
                "token": token,
                "error": "User not found.",
                "route_prefix": "/secure"
            })
    except Exception as e:
        print(f"Error updating password: {str(e)}")
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "token": token,
            "error": "Error updating password. Please try again.",
            "route_prefix": "/secure"
        })

# We will add other secure endpoints (/forgot-password, /change-password, etc.) here

# --- VULNERABLE ENDPOINTS (For comparison, not in secure_main) ---
# @app.post("/search")... (vulnerable command injection)
# @app.post("/save_preferences")... (vulnerable deserialization)
# @app.get("/files/{filename}")... (vulnerable path traversal)
# @app.get("/profile")... (vulnerable XSS) 