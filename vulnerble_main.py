from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from database import get_db
from models import User, Customer
from sqlalchemy import text
import pickle
import os
import subprocess
from passlib.hash import pbkdf2_sha256
import hashlib
import secrets
from fastapi import Cookie
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_utils import send_reset_code

app = FastAPI()
templates = Jinja2Templates(directory="templates")

reset_tokens = {}  # {token: email}
reset_codes = {}   # {email: {"code": code, "expires": expiration_time}}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    # Check for existing username
    username_check = f"SELECT * FROM users WHERE username = '{username}'"
    existing_username = db.execute(text(username_check)).fetchone()
    if existing_username:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Username already taken"
        })

    # Check for existing email
    email_check = f"SELECT * FROM users WHERE email = '{email}'"
    existing_email = db.execute(text(email_check)).fetchone()
    if existing_email:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Email already registered"
        })

    # If no duplicates, proceed with registration
    hashed = hashlib.sha256(password.encode()).hexdigest()
    sql = f"""
        INSERT INTO users (username, email, hashed_password, salt)
        VALUES ('{username}', '{email}', '{hashed}', 'sha256')
    """
    db.execute(text(sql))
    db.commit()
    return templates.TemplateResponse("register.html", {
        "request": request,
        "message": "Registration successful! Please login."
    })

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Use simple SHA-256 hash for demonstration (vulnerable to SQL injection)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Construct SQL query with both username and hashed password
    # This is vulnerable to SQL injection via username
    sql = f"""
        SELECT * FROM users
        WHERE username = '{username}' AND hashed_password = '{hashed_password}'
    """
    
    print("RUNNING VULNERABLE QUERY:", sql)  # For debugging
    
    result = db.execute(text(sql)).fetchone()
    
    if result:
        response = RedirectResponse(url="/add-customer", status_code=303)
        response.set_cookie(key="logged_in", value="true", httponly=True)
        return response
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

# Helper function to check login
def require_login(request: Request):
    if request.cookies.get("logged_in") != "true":
        return False
    return True

@app.get("/add-customer", response_class=HTMLResponse)
def customer_form(request: Request):
    if not require_login(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("add_customer.html", {"request": request})

@app.post("/add-customer", response_class=HTMLResponse)
def add_customer(request: Request, name: str = Form(...), email: str = Form(...),
                 phone: str = Form(...), address: str = Form(...),
                 db: Session = Depends(get_db)):
    if not require_login(request):
        return RedirectResponse(url="/login", status_code=303)
    
    # Direct SQL insertion without error handling (vulnerable to SQL injection)
    sql = f"""
        INSERT INTO customers (name, email, phone, address)
        VALUES ('{name}', '{email}', '{phone}', '{address}')
    """
    
    print("RUNNING VULNERABLE QUERY:", sql)  # For debugging
    
    db.execute(text(sql))
    db.commit()
    return templates.TemplateResponse("add_customer.html", {
        "request": request,
        "message": f"Customer '{name}' added!"
        ,"is_vulnerable": True
    })

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_form(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password")
def forgot_password(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    sql = f"SELECT * FROM users WHERE email = '{email}'"
    result = db.execute(text(sql)).fetchone()
    if result:
        # Generate code using email and timestamp for uniqueness
        timestamp = datetime.now().timestamp()
        code = hashlib.sha1(f"{email}{timestamp}".encode()).hexdigest()
        
        # Store code with expiration time (5 minutes)
        reset_codes[email] = {
            "code": code,
            "expires": datetime.now() + timedelta(minutes=5)
        }
        
        # Send the reset code via email
        if send_reset_code(email, code):
            print(f"Reset code sent to {email}: {code}")
            return RedirectResponse(url="/enter-code?email=" + email, status_code=303)
        else:
            return templates.TemplateResponse("forgot_password.html", {
                "request": request,
                "error": "Failed to send reset code. Please try again."
            })
    
    # Return a generic message to avoid exposing valid emails
    return templates.TemplateResponse("forgot_password.html", {
        "request": request,
        "message": "If a user with that email exists, a reset code has been sent."
    })

@app.get("/enter-code", response_class=HTMLResponse)
def enter_code_form(request: Request, email: str = ""):
    return templates.TemplateResponse("enter_code.html", {"request": request, "email": email})

@app.post("/enter-code")
def enter_code(request: Request, code: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    if email not in reset_codes:
        return HTMLResponse("No reset code found. Please request a new one.", status_code=400)
    
    stored_data = reset_codes[email]
    if datetime.now() > stored_data["expires"]:
        del reset_codes[email]  # Remove expired code
        return HTMLResponse("Reset code has expired. Please request a new one.", status_code=400)
    
    if code == stored_data["code"]:
        # Generate a token for password reset
        token = secrets.token_urlsafe(16)
        reset_tokens[token] = email
        return RedirectResponse(url=f"/reset-password/{token}", status_code=303)
    
    return HTMLResponse("Invalid code", status_code=400)

@app.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_form(request: Request, token: str):
    if token not in reset_tokens:
        return HTMLResponse("Invalid or expired token", status_code=400)
    return templates.TemplateResponse("change_password.html", {"request": request, "token": token})

@app.post("/reset-password/{token}", response_class=HTMLResponse)
def reset_password(token: str, new_password: str = Form(...), confirm_password: str = Form(...), db: Session = Depends(get_db)):
    if token not in reset_tokens:
        return HTMLResponse("Invalid or expired token", status_code=400)
    if new_password != confirm_password:
        return HTMLResponse("Passwords do not match", status_code=400)
    email = reset_tokens.pop(token)
    
    # Check which hashing algorithm to use based on the user's salt
    sql = f"SELECT salt FROM users WHERE email = '{email}'"
    result = db.execute(text(sql)).fetchone()
    
    if result and result.salt == "pbkdf2_managed":
        # User is from secure version, use PBKDF2
        hashed_password = pbkdf2_sha256.hash(new_password)
    else:
        # User is from vulnerable version, use SHA-256
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    
    sql = f"UPDATE users SET hashed_password = '{hashed_password}' WHERE email = '{email}'"
    db.execute(text(sql))
    db.commit()
    
    # Remove the reset code only after successful password change
    if email in reset_codes:
        reset_codes.pop(email)
    
    return HTMLResponse("Password has been reset successfully!", status_code=200)

@app.get("/change-password", response_class=HTMLResponse)
def change_password_form(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

@app.post("/change-password")
def change_password(current_password: str = Form(...), new_password: str = Form(...),
                   confirm_password: str = Form(...), db: Session = Depends(get_db)):
    if new_password != confirm_password:
        return {"error": "Passwords do not match"}
    sql = f"SELECT * FROM users WHERE hashed_password IS NOT NULL"
    users = db.execute(text(sql)).fetchall()
    for user in users:
        if pbkdf2_sha256.verify(current_password, user.hashed_password):
            new_hashed = pbkdf2_sha256.hash(new_password)
            update_sql = f"UPDATE users SET hashed_password = '{new_hashed}' WHERE id = {user.id}"
            db.execute(text(update_sql))
            db.commit()
            return {"message": "Password changed successfully (PBKDF2)"}
    return {"error": "Current password incorrect"}

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="logged_in")
    return response
