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
import html  # i Added this import for HTML escaping
from email_utils import send_reset_code
from security import is_login_blocked, validate_password # Import necessary functions from security.py

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
    # Check password complexity using validate_password from security.py
    is_valid, error_message = validate_password(password)
    if not is_valid:
         return templates.TemplateResponse("register.html", {
             "request": request,
             "error": error_message,
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
    
    # Add initial password to history
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

    if user:
        # Check if login is blocked
        if is_login_blocked(user.last_failed_login, user.failed_login_attempts):
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Account is temporarily locked due to too many failed login attempts.",
                "route_prefix": "/secure"
            })
            
        if pbkdf2_sha256.verify(password, user.hashed_password):
            # Successful login: reset failed attempts
            user.failed_login_attempts = 0
            user.last_failed_login = None
            db.commit()

            # Generate session token
            session_token = secrets.token_urlsafe(32)
            active_sessions.add(session_token)
            
            response = RedirectResponse(url="/secure/add-customer", status_code=303)
            response.set_cookie(key="session_token", value=session_token, httponly=True, secure=False)
            return response
        else:
            # Failed login: increment failed attempts and update last failed login time
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()
            db.commit()

            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Invalid credentials",
                "route_prefix": "/secure"
            })
    else:
        # User not found: also increment a counter or use a delayed response to prevent enumeration
        # For simplicity here, just return generic error
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
        # Check if account is locked due to failed login attempts
        if is_login_blocked(user.last_failed_login, user.failed_login_attempts):
             return templates.TemplateResponse("forgot_password.html", {
                 "request": request,
                 "error": "Account is temporarily locked due to too many failed login attempts. Please try again later.",
                 "route_prefix": "/secure"
             })

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
        # Return a generic message to avoid exposing valid emails
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
            # Check against password history
            # Fetch last N passwords (excluding the current one if it's being changed)
            password_history = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).order_by(PasswordHistory.timestamp.desc()).limit(config.password_config.PASSWORD_HISTORY).all()
            
            # Check if the new password is in history
            new_hashed_password = pbkdf2_sha256.hash(new_password)
            for history_entry in password_history:
                if pbkdf2_sha256.verify(new_password, history_entry.hashed_password):
                     return templates.TemplateResponse("change_password.html", {
                         "request": request,
                         "token": token,
                         "error": f"New password cannot be one of your last {config.password_config.PASSWORD_HISTORY} passwords.",
                         "route_prefix": "/secure"
                     })


            # Update the password
            user.hashed_password = new_hashed_password
            
            # Add new password to history
            new_history_entry = PasswordHistory(
                user_id=user.id,
                hashed_password=new_hashed_password
            )
            db.add(new_history_entry)

            # Clean up old history entries if exceeding the limit
            current_history_count = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).count()
            if current_history_count > config.password_config.PASSWORD_HISTORY:
                 oldest_entries = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).order_by(PasswordHistory.timestamp.asc()).limit(current_history_count - config.password_config.PASSWORD_HISTORY).all()
                 for entry in oldest_entries:
                     db.delete(entry)


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
        db.rollback() # Rollback changes in case of error
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "token": token,
            "error": "Error updating password. Please try again.",
            "route_prefix": "/secure"
        })

@app.get("/secure/change-password", response_class=HTMLResponse)
def change_password_form_secure(request: Request, authenticated: bool = Depends(require_secure_login)):
    # This endpoint is for authenticated users to change their password
    # It's different from the reset password flow
    return templates.TemplateResponse("change_password.html", {"request": request, "route_prefix": "/secure", "token": None})

@app.post("/secure/change-password", response_class=HTMLResponse)
def change_password_secure(request: Request, current_password: str = Form(...), new_password: str = Form(...),
                   confirm_password: str = Form(...), db: Session = Depends(get_db), authenticated: bool = Depends(require_secure_login)):
    # This endpoint is for authenticated users to change their password
    # It's different from the reset password flow

    # Get the current logged-in user (you'd need a way to get the user from the session token)
    # For this example, let's assume you can get the user object based on authentication
    # Replace this with your actual logic to get the authenticated user
    user = db.query(User).filter(User.username == "<logged_in_username>").first() # Replace with actual user retrieval

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "New passwords do not match.",
            "route_prefix": "/secure",
            "token": None
        })

    # Verify current password
    if not pbkdf2_sha256.verify(current_password, user.hashed_password):
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "Invalid current password.",
            "route_prefix": "/secure",
            "token": None
        })

    # Check against password history
    password_history = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).order_by(PasswordHistory.timestamp.desc()).limit(config.password_config.PASSWORD_HISTORY).all()
    new_hashed_password = pbkdf2_sha256.hash(new_password)
    for history_entry in password_history:
        if pbkdf2_sha256.verify(new_password, history_entry.hashed_password):
             return templates.TemplateResponse("change_password.html", {
                 "request": request,
                 "error": f"New password cannot be one of your last {config.password_config.PASSWORD_HISTORY} passwords.",
                 "route_prefix": "/secure",
                 "token": None
             })


    try:
        # Update the password
        user.hashed_password = new_hashed_password

        # Add new password to history
        new_history_entry = PasswordHistory(
            user_id=user.id,
            hashed_password=new_hashed_password
        )
        db.add(new_history_entry)

        # Clean up old history entries if exceeding the limit
        current_history_count = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).count()
        if current_history_count > config.password_config.PASSWORD_HISTORY:
             oldest_entries = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).order_by(PasswordHistory.timestamp.asc()).limit(current_history_count - config.password_config.PASSWORD_HISTORY).all()
             for entry in oldest_entries:
                 db.delete(entry)

        db.commit()

        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "message": "Password changed successfully.",
            "route_prefix": "/secure",
            "token": None
        })
    except Exception as e:
        print(f"Error updating password: {str(e)}")
        db.rollback() # Rollback changes in case of error
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "Error updating password. Please try again.",
            "route_prefix": "/secure",
            "token": None
        })

@app.get("/secure/logout")
def secure_logout():
    response = RedirectResponse(url="/secure/login", status_code=303)
    # Invalidate session token (remove from active_sessions set)
    session_token = Cookie(None)(__request=Request)
    if session_token in active_sessions:
        active_sessions.remove(session_token)
    response.delete_cookie(key="session_token")
    return response

# We will add other secure endpoints (/forgot-password, /change-password, etc.) here

# --- VULNERABLE ENDPOINTS (For comparison, not in secure_main) ---
# @app.post("/search")... (vulnerable command injection)
# @app.post("/save_preferences")... (vulnerable deserialization)
# @app.get("/files/{filename}")... (vulnerable path traversal)
# @app.get("/profile")... (vulnerable XSS) 