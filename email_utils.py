import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_reset_code(to_email: str, reset_code: str):
    # Email configuration
    sender_email = "roeishriki123@gmail.com"
    sender_password = "jwuc tlel vmts jngv"
    
    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "Your Password Reset Code"
    
    # Simple email body with the reset code
    body = f"Your password reset code is: {reset_code}"
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        # Create SMTP session
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        
        # Login to the server
        server.login(sender_email, sender_password)
        
        # Send email
        text = msg.as_string()
        server.sendmail(sender_email, to_email, text)
        
        # Close the server connection
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False 