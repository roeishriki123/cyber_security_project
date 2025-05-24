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

app = FastAPI()
templates = Jinja2Templates(directory="templates")

reset_tokens = {}  # {token: email}
reset_codes = {}   # {email: code}

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

@app.post("/search")
def search(query: str = Form(...)):
    result = subprocess.check_output(f"grep -r {query} .", shell=True)
    return {"results": result.decode()}

@app.post("/save_preferences")
def save_preferences(preferences: str = Form(...)):
    user_prefs = pickle.loads(preferences.encode())
    return {"status": "Preferences saved"}

@app.get("/files/{filename}")
def get_file(filename: str):
    file_path = os.path.join("uploads", filename)
    with open(file_path, "r") as f:
        return {"content": f.read()}

@app.get("/profile")
def profile(request: Request):
    user_input = request.query_params.get("name", "")
    return templates.TemplateResponse("base.html", {
        "request": request,
        "user_input": user_input
    })

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_form(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password")
def forgot_password(email: str = Form(...), db: Session = Depends(get_db)):
    sql = f"SELECT * FROM users WHERE email = '{email}'"
    result = db.execute(text(sql)).fetchone()
    if result:
        random_value = secrets.token_urlsafe(16)
        code = hashlib.sha1(random_value.encode()).hexdigest()
        reset_codes[email] = code
        print(f"Simulated email to {email}: Your reset code is: {code}")
        return RedirectResponse(url="/enter-code?email=" + email, status_code=303)
    return HTMLResponse("Email not found", status_code=400)

@app.get("/enter-code", response_class=HTMLResponse)
def enter_code_form(request: Request, email: str = ""):
    return templates.TemplateResponse("enter_code.html", {"request": request, "email": email})

@app.post("/enter-code")
def enter_code(request: Request, code: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    for user_email, stored_code in reset_codes.items():
        if code == stored_code:
            # Generate a token for password reset
            token = secrets.token_urlsafe(16)
            reset_tokens[token] = user_email
            reset_codes.pop(user_email)
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
    hashed_password = pbkdf2_sha256.hash(new_password)
    sql = f"UPDATE users SET hashed_password = '{hashed_password}' WHERE email = '{email}'"
    db.execute(text(sql))
    db.commit()
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
