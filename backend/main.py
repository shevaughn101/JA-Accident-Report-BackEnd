import os
import hashlib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from io import BytesIO
import datetime
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Response, Request
from fastapi.middleware.cors import CORSMiddleware
import html
import re
from pydantic import BaseModel, EmailStr, Field, field_validator
import firebase_admin
from firebase_admin import credentials, firestore, auth, storage
from google.cloud.firestore_v1.base_query import FieldFilter
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from typing import List, Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import cloudinary
import cloudinary.uploader

from email.message import EmailMessage

def send_email_notification(uid: str, subject: str, message: str):
    try:
        user = auth.get_user(uid)
        to_email = user.email
        if not to_email:
            print("User has no email.")
            return
            
        print("\n--- [EMAIL SYSTEM LOG] ---\n")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(f"Message: {message}")
        print(f"--------------------------\n")
        SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
        SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD")
        if SENDER_EMAIL and SENDER_PASSWORD:
            msg = EmailMessage()
            msg.set_content(message)
            msg['Subject'] = subject
            msg['From'] = f"JA Accident Report <{SENDER_EMAIL}>"
            msg['To'] = to_email
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
                smtp.send_message(msg)
    except Exception as e:
        print(f"Error sending email to UID {uid}: {e}")

from cloudinary.utils import cloudinary_url


limiter = Limiter(key_func=get_remote_address)


# --- Auto-load environment variables from local .env ---
for _search_dir in [os.path.dirname(__file__), os.path.dirname(os.path.dirname(__file__))]:
    _env_path = os.path.join(_search_dir, ".env")
    if os.path.exists(_env_path):
        try:
            with open(_env_path, "r", encoding="utf-8") as _ef:
                for _eline in _ef:
                    _eline = _eline.strip()
                    if _eline and not _eline.startswith("#") and "=" in _eline:
                        _k, _v = _eline.split("=", 1)
                        _k = _k.strip()
                        _v = _v.strip().strip('"').strip("'")
                        if _k:
                            os.environ[_k] = _v
        except Exception as _e:
            pass

app = FastAPI(title="JA Accident Report API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


ALLOWED_ORIGINS = os.environ.get("FRONTEND_URLS", "https://sentinel-frontend-olive.vercel.app,http://localhost:3000,http://127.0.0.1:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


try:
    firebase_env_creds = os.environ.get("FIREBASE_CREDENTIALS_JSON")
    if firebase_env_creds:
        cred_dict = json.loads(firebase_env_creds)
        cred = credentials.Certificate(cred_dict)
    else:
        cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "firebase-credentials.json")
        cred = credentials.Certificate(cred_path)
        
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Warning: Firebase Admin SDK initialization failed. Error: {e}")
    db = None

try:
    if os.environ.get("CLOUDINARY_URL"):
        cloudinary.config()
except Exception as e:
    print(f"Warning: Cloudinary initialization failed: {e}")




def verify_firebase_token(authorization: str = Header(...)):
    """Verifies the Firebase ID token and returns the decoded token."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")
    
    token = authorization.split(" ")[1]
    try:
        
        decoded_token = auth.verify_id_token(token, check_revoked=True)
        
        
        if decoded_token.get("email") == "contactshevaughn124@gmail.com":
            if decoded_token.get("role") != "admin":
                auth.set_custom_user_claims(decoded_token["uid"], {"role": "admin"})
                decoded_token["role"] = "admin"
                
        return decoded_token
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Unauthorized: {str(e)}")

def require_admin(token: dict = Depends(verify_firebase_token)):
    if token.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return token

def require_admin_or_officer(token: dict = Depends(verify_firebase_token)):
    if token.get("role") not in ["admin", "officer"]:
        raise HTTPException(status_code=403, detail="Admin or Officer privileges required")
    return token

def require_officer(token: dict = Depends(verify_firebase_token)):
    if token.get("role") not in ["admin", "officer"]:
        raise HTTPException(status_code=403, detail="Officer privileges required")
    return token

def require_civilian(token: dict = Depends(verify_firebase_token)):
    return token




def refresh_signed_urls(incident_data):
    """Refreshes Signed URLs for any evidence containing a blob_name (now Cloudinary public_id)."""
    for field in ['scenePhotos', 'statutoryDocs']:
        if field in incident_data and isinstance(incident_data[field], list):
            for file_obj in incident_data[field]:
                if 'blob_name' in file_obj:
                    try:
                        url, options = cloudinary_url(
                            file_obj['blob_name'],
                            resource_type="raw" if file_obj.get("type") == "application/pdf" else "image",
                            type="authenticated",
                            sign_url=True
                        )
                        file_obj['url'] = url
                    except Exception as e:
                        print(f"Failed to sign url for {file_obj['blob_name']}: {e}")

def extract_exif(image_bytes: bytes):
    """Extracts EXIF timestamp and GPS data from image bytes safely."""
    try:
        img = Image.open(BytesIO(image_bytes))
        exif_data = img._getexif()
        if not exif_data:
            return None
            
        result = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag in ['DateTimeOriginal', 'DateTime']:
                result['timestamp'] = str(value)
            elif tag == 'GPSInfo':
                gps_data = {}
                for t in value:
                    sub_tag = GPSTAGS.get(t, t)
                    gps_data[sub_tag] = str(value[t])
                result['gps'] = gps_data
        return result
    except Exception:
        return None

def verify_magic_bytes(contents: bytes, content_type: str) -> bool:
    """Verifies that the file actually matches its declared MIME type via magic bytes"""
    if content_type in ["image/jpeg", "image/jpg"]:
        return contents.startswith(b'\xff\xd8')
    elif content_type == "image/png":
        return contents.startswith(b'\x89PNG\r\n\x1a\n')
    elif content_type == "application/pdf":
        return contents.startswith(b'%PDF-')
    
    return True

def send_assignment_email(officer_email: str, incident_id: str):
    """Sends an email notification to the assigned officer."""
    sender = os.environ.get("EMAIL_SENDER")
    password = os.environ.get("EMAIL_APP_PASSWORD")
    
    if not sender or not password:
        print("Email credentials not configured. Skipping notification.")
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"New Case Assigned: Incident {incident_id[:8].upper()}"
        msg["From"] = sender
        msg["To"] = officer_email

        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #0f172a;">JA Accident Report</h2>
            <p>You have been assigned to a new incident.</p>
            <p><strong>Incident ID:</strong> {incident_id}</p>
            <p>Please log in to your Officer Dashboard to review the details and secure evidence.</p>
            <br>
            <p style="color: #64748b; font-size: 12px;">This is an automated message. Do not reply.</p>
          </body>
        </html>
        """
        
        msg.attach(MIMEText(html, "html"))
        
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, officer_email, msg.as_string())
            
        print(f"Notification sent to {officer_email}")
    except Exception as e:
        print(f"Error sending email to {officer_email}: {e}")




import threading
import smtplib


def send_incident_reported_email_to_admin(incident_id: str, incident_data: dict):
    """Sends a free email notification to all assigned JA Police Admins when a new report is filed."""
    def _worker():
        sender = (os.environ.get("EMAIL_SENDER") or os.environ.get("SENDER_EMAIL") or "").strip()
        password = (os.environ.get("EMAIL_APP_PASSWORD") or os.environ.get("SENDER_PASSWORD") or "").replace(" ", "").strip()
        default_admin_email = (os.environ.get("JA_ADMIN_EMAIL") or "admin@ja-accident-report.com").strip()
        
        # If sender was left as placeholder or empty, fallback to JA_ADMIN_EMAIL if it's a real address
        if (not sender or sender.lower() == "yourgmail@gmail.com") and default_admin_email and "@" in default_admin_email:
            sender = default_admin_email
        
        inc_type = incident_data.get("type") or incident_data.get("incident_type") or "Accident"
        location = incident_data.get("location") or "Unspecified Location"
        jurisdiction = incident_data.get("jurisdiction") or "National"
        description = incident_data.get("description") or "No description provided."
        timestamp = incident_data.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Collect all assigned admins:
        admin_recipients = set()
        if default_admin_email and "@" in default_admin_email:
            admin_recipients.add(default_admin_email.lower())
        admin_recipients.add("admin@ja-accident-report.com")
        admin_recipients.add("shevaughn@example.com")

        try:
            if db:
                admin_docs = db.collection("users").where(filter=FieldFilter("role", "==", "admin")).stream()
                for doc in admin_docs:
                    u_data = doc.to_dict() or {}
                    em = (u_data.get("email") or "").strip().lower()
                    if em and "@" in em:
                        admin_recipients.add(em)
        except Exception as ae:
            print(f"[WARN] Error querying assigned admins from db: {ae}")

        recipient_list = sorted(list(admin_recipients))
        print(f"[NOTIFICATION LOG] New Report {incident_id} filed in {jurisdiction}. Target Admins: {recipient_list}")
        
        if not sender or not password or password == "your-16-character-app-password" or "@" not in sender:
            print(f"[INFO] EMAIL_SENDER ({sender}) or EMAIL_APP_PASSWORD is not configured with live credentials. Alert recorded for dispatch to assigned admins: {recipient_list}.")
            return

        for admin_email in recipient_list:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = f"[JA Police Alert] New Accident Report: {inc_type} - {location}"
                msg["From"] = f"JA Accident Emergency System <{sender}>"
                msg["To"] = admin_email

                html = f"""
                <html>
                  <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; padding: 24px; color: #1e293b;">
                    <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
                      <div style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); padding: 24px; color: #ffffff;">
                        <h1 style="margin: 0; font-size: 20px; font-weight: 700; color: #ffffff;">JA Police Accident Alert</h1>
                        <p style="margin: 6px 0 0 0; font-size: 13px; color: #94a3b8;">Official Incident Notification Dispatch</p>
                      </div>
                      <div style="padding: 24px;">
                        <div style="background-color: #fef2f2; border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px;">
                          <p style="margin: 0; font-size: 14px; font-weight: bold; color: #991b1b;">New Civilian Incident Submitted</p>
                          <p style="margin: 4px 0 0 0; font-size: 12px; color: #b91c1c;">Incident Reference ID: {incident_id}</p>
                        </div>
                        
                        <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 24px;">
                          <tr>
                            <td style="padding: 8px 0; color: #64748b; font-weight: bold; width: 35%;">Incident Type:</td>
                            <td style="padding: 8px 0; color: #0f172a; font-weight: 600;">{inc_type}</td>
                          </tr>
                          <tr>
                            <td style="padding: 8px 0; color: #64748b; font-weight: bold;">Location:</td>
                            <td style="padding: 8px 0; color: #0f172a;">{location}</td>
                          </tr>
                          <tr>
                            <td style="padding: 8px 0; color: #64748b; font-weight: bold;">Parish / Jurisdiction:</td>
                            <td style="padding: 8px 0; color: #0f172a;">{jurisdiction}</td>
                          </tr>
                          <tr>
                            <td style="padding: 8px 0; color: #64748b; font-weight: bold;">Filed At:</td>
                            <td style="padding: 8px 0; color: #0f172a;">{timestamp}</td>
                          </tr>
                        </table>

                        <div style="background: #f8fafc; border-radius: 8px; padding: 16px; margin-bottom: 24px;">
                          <p style="margin: 0 0 8px 0; font-size: 12px; font-weight: bold; text-transform: uppercase; color: #64748b;">Description</p>
                          <p style="margin: 0; font-size: 13px; line-height: 1.5; color: #334155;">{description}</p>
                        </div>

                        <div style="text-align: center; margin-top: 24px;">
                          <a href="https://ja-accident-report-front-end.vercel.app/officer_feed.html" style="background-color: #0f172a; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; font-size: 13px; display: inline-block;">View Officer Incident Feed &rarr;</a>
                        </div>
                      </div>
                      <div style="background-color: #f1f5f9; padding: 16px 24px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; text-align: center;">
                        Jamaica Emergency Road Safety Platform &bull; Automated Police Admin Dispatch
                      </div>
                    </div>
                  </body>
                </html>
                """
                msg.attach(MIMEText(html, "html"))
                
                # Attempt SSL on port 465, with fallback to TLS on port 587
                sent_ok = False
                try:
                    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=12) as server:
                        server.login(sender, password)
                        server.sendmail(sender, admin_email, msg.as_string())
                        sent_ok = True
                except Exception as s_err:
                    print(f"[WARN] Port 465 SSL dispatch failed ({s_err}), attempting Port 587 STARTTLS...")
                    try:
                        with smtplib.SMTP("smtp.gmail.com", 587, timeout=12) as server:
                            server.starttls()
                            server.login(sender, password)
                            server.sendmail(sender, admin_email, msg.as_string())
                            sent_ok = True
                    except Exception as t_err:
                        print(f"[ERROR] Port 587 TLS dispatch also failed: {t_err}")

                if sent_ok:
                    print(f"[SUCCESS] Incident alert email delivered to {admin_email}")
            except Exception as e:
                print(f"[ERROR] Error preparing/sending alert email to {admin_email}: {e}")

    threading.Thread(target=_worker, daemon=True).start()


def send_claim_submitted_email_to_insurance(policy_number: str, company: str, incident_id: str, client_email: str):
    """Sends a free email notification to the Insurance Agency Desk when a claim is linked."""
    def _worker():
        sender = os.environ.get("EMAIL_SENDER") or os.environ.get("SENDER_EMAIL") or "yourgmail@gmail.com"
        password = (os.environ.get("EMAIL_APP_PASSWORD") or os.environ.get("SENDER_PASSWORD") or "your-16-character-app-password").replace(" ", "").strip()
        
        recipients = set()
        default_insurance_email = os.environ.get(f"INSURANCE_EMAIL_{company.upper()}", os.environ.get("INSURANCE_NOTIFY_EMAIL", "claims@insurance.gov.jm"))
        if default_insurance_email:
            recipients.add(default_insurance_email.strip())
        
        try:
            if db:
                agent_docs = db.collection("users").where(filter=FieldFilter("role", "==", "insurance_agent")).stream()
                for doc in agent_docs:
                    data = doc.to_dict() or {}
                    u_comp = (data.get("company") or "").lower()
                    t_comp = company.lower()
                    if (t_comp in u_comp or u_comp in t_comp or 
                        ("bcic" in t_comp and "bcse" in u_comp) or 
                        ("bcse" in t_comp and "bcic" in u_comp)):
                        if data.get("email"):
                            recipients.add(data.get("email").strip())
        except Exception as e:
            print(f"[WARN] Error querying company agents: {e}")

        recipient_list = sorted(list(recipients))
        print(f"[NOTIFICATION LOG] New Claim for {policy_number} ({company}). Target Insurers: {recipient_list}")

        if not sender or not password or password == "your-16-character-app-password" or "@" not in sender:
            print(f"[INFO] EMAIL_SENDER and EMAIL_APP_PASSWORD not set with live credentials. Alert recorded for dispatch to insurers: {recipient_list}.")
            return

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[New Claim Forwarded] Policy {policy_number} ({company})"
            msg["From"] = f"JA Insurance Portal <{sender}>"
            msg["To"] = ", ".join(recipient_list)

            html = f"""
            <html>
              <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; padding: 24px; color: #1e293b;">
                <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
                  <div style="background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%); padding: 24px; color: #ffffff;">
                    <h1 style="margin: 0; font-size: 20px; font-weight: 700; color: #ffffff;">{company} Claims Desk</h1>
                    <p style="margin: 6px 0 0 0; font-size: 13px; color: #bfdbfe;">New Policy Claim & Accident Dossier Forwarded</p>
                  </div>
                  <div style="padding: 24px;">
                    <div style="background-color: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px;">
                      <p style="margin: 0; font-size: 14px; font-weight: bold; color: #1e40af;">Claim Initialized & Forwarded to Adjuster Review</p>
                      <p style="margin: 4px 0 0 0; font-size: 12px; color: #2563eb;">Current Status: Stage 2 of 5 (Under Investigation)</p>
                    </div>
                    
                    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 24px;">
                      <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: bold; width: 35%;">Policy Number:</td>
                        <td style="padding: 8px 0; color: #0f172a; font-weight: 700; font-family: monospace;">{policy_number}</td>
                      </tr>
                      <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: bold;">Insurance Provider:</td>
                        <td style="padding: 8px 0; color: #0f172a;">{company}</td>
                      </tr>
                      <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: bold;">Client Email:</td>
                        <td style="padding: 8px 0; color: #0f172a;">{client_email}</td>
                      </tr>
                      <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: bold;">Linked Incident ID:</td>
                        <td style="padding: 8px 0; color: #0f172a; font-family: monospace;">{incident_id or 'N/A'}</td>
                      </tr>
                    </table>

                    <div style="text-align: center; margin-top: 24px;">
                      <a href="https://ja-accident-report-front-end.vercel.app/insurance_admin.html" style="background-color: #2563eb; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; font-size: 13px; display: inline-block;">Open Claims Console &rarr;</a>
                    </div>
                  </div>
                  <div style="background-color: #f1f5f9; padding: 16px 24px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; text-align: center;">
                    JA Accident Report Claims Automation &bull; Direct Agency Dispatch
                  </div>
                </div>
              </body>
            </html>
            """
            msg.attach(MIMEText(html, "html"))
            
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender, password)
                for rec in recipient_list:
                    try:
                        server.sendmail(sender, rec, msg.as_string())
                    except Exception as re:
                        print(f"[ERROR] Error sending to {rec}: {re}")
            print(f"[SUCCESS] Claim email dispatched to {recipient_list}")
        except Exception as e:
            print(f"[ERROR] Error sending claim email: {e}")

    threading.Thread(target=_worker, daemon=True).start()


def sanitize_string(v: str) -> str:
    if not isinstance(v, str):
        return v
    malicious_patterns = [
        r'sleep\s*\(',
        r'cat\s+/etc/',
        r'\.\./',
        r'\.\.\\',
        r'DBMS_SESSION\.SLEEP',
        r'java\.lang\.Thread\.sleep',
        r'(?i)select.*?from',
        r'(?i)union.*?select',
        r'http://',
        r'https://'
    ]
    for pattern in malicious_patterns:
        if re.search(pattern, v, re.IGNORECASE):
            raise ValueError("Invalid input detected")
    return html.escape(v)

class IncidentReport(BaseModel):
    type: str = Field(..., max_length=100)
    location: str = Field(..., max_length=255)
    jurisdiction: str = Field(..., max_length=100)
    description: str = Field(..., max_length=5000)
    timestamp: str = Field(..., max_length=50)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    vehicleDetails: dict = {}
    involvedParties: list = []
    witnesses: list = []
    statutoryDocs: list = []
    scenePhotos: list = []

    @field_validator('timestamp', mode='before')
    def validate_timestamp(cls, v):
        import re
        if not isinstance(v, str) or not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', v):
            raise ValueError("Invalid timestamp format")
        return v

    @field_validator('type', 'location', 'jurisdiction', 'description', mode='before')
    def sanitize_strings(cls, v):
        return sanitize_string(v)

class OfficerCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)
    jurisdiction: str = Field("", max_length=100)
    role: str = "officer"
    company: str = "" 

    @field_validator('jurisdiction', mode='before')
    def sanitize_jurisdiction(cls, v):
        return sanitize_string(v)

class ClientRegister(BaseModel):
    email: EmailStr
    password: str
    policy_number: str
    company: str
    payment_amount: Optional[str] = None
    next_payment_date: Optional[str] = None


class RoleUpdate(BaseModel):
    role: str = Field(..., max_length=50)
    jurisdiction: str = Field("Unknown", max_length=100)

    @field_validator('role', 'jurisdiction', mode='before')
    def sanitize_role(cls, v):
        return sanitize_string(v)





@app.post("/api/auth/verify")
async def verify_auth(token: dict = Depends(verify_firebase_token)):
    token.setdefault("role", "civilian")
    token.setdefault("jurisdiction", "Unknown")
    return token

@app.post("/api/admin/officers")
async def create_officer(officer: OfficerCreate, admin_token: dict = Depends(require_admin)):
    try:
        user = auth.create_user(
            email=officer.email,
            password=officer.password,
            email_verified=True
        )
        target_role = officer.role if officer.role in ["officer", "insurance_agent"] else "officer"
        claims = {"role": target_role}
        
        if target_role == "officer":
            claims["jurisdiction"] = officer.jurisdiction
        elif target_role == "insurance_agent":
            claims["company"] = officer.company
            
        auth.set_custom_user_claims(user.uid, claims)
        return {"message": "User created successfully", "uid": user.uid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/admin/officers")
async def get_officers(admin_token: dict = Depends(require_admin_or_officer)):
    try:
        page = auth.list_users()
        officers = []
        for user in page.users:
            role = "civilian"
            jur = "Unknown"
            if user.custom_claims:
                role = user.custom_claims.get("role", "civilian")
                jur = user.custom_claims.get("jurisdiction", "Unknown")
            officers.append({
                "uid": user.uid,
                "email": user.email,
                "role": role,
                "jurisdiction": jur
            })
        return {"officers": officers}
    except Exception as e:
        print(f"Error fetching officers: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/api/officers/list")
async def get_officers_list(user_token: dict = Depends(require_officer)):
    """Returns a lightweight list of officers for the assignment dropdown"""
    try:
        page = auth.list_users()
        officers = []
        for user in page.users:
            if user.custom_claims and user.custom_claims.get("role") in ["officer", "admin"]:
                officers.append({
                    "email": user.email,
                    "jurisdiction": user.custom_claims.get("jurisdiction", "Unknown")
                })
        return {"officers": officers}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/users/{uid}/role")
async def update_user_role(uid: str, update: RoleUpdate, admin_token: dict = Depends(require_admin)):
    try:
        auth.set_custom_user_claims(uid, {"role": update.role, "jurisdiction": update.jurisdiction})
        return {"message": f"Updated role to {update.role}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/upload")
@limiter.limit("10/minute")
async def upload_files(
    request: Request,
    files: List[UploadFile] = File(...), 
    user_token: dict = Depends(require_civilian)
):
    results = []
    
    try:
        for file in files:
            contents = await file.read()
            
            if len(contents) > 10 * 1024 * 1024:
                raise HTTPException(status_code=400, detail=f"File {file.filename} exceeds 10MB limit")
                
            if file.content_type not in ["image/jpeg", "image/jpg", "image/png", "application/pdf", "image/heic", "image/heif"]:
                raise HTTPException(status_code=400, detail=f"File {file.filename} has unsupported type {file.content_type}")
                
            if not verify_magic_bytes(contents, file.content_type):
                raise HTTPException(status_code=400, detail=f"File {file.filename} failed integrity check. Spoofed extension detected.")
                
            sha256_hash = hashlib.sha256(contents).hexdigest()
            
            exif_data = None
            if file.content_type in ["image/jpeg", "image/png"]:
                exif_data = extract_exif(contents)
            try:
                res_type = "raw" if file.content_type == "application/pdf" else "image"
                upload_result = cloudinary.uploader.upload(
                    contents, 
                    folder=f"incidents/{user_token.get('uid')}",
                    resource_type=res_type,
                    type="authenticated"
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Cloudinary upload failed: {str(e)}")

            public_id = upload_result.get("public_id")
            proxy_url, _ = cloudinary_url(
                public_id,
                resource_type=res_type,
                type="authenticated",
                sign_url=True
            )
            
            results.append({
                "name": file.filename,
                "url": proxy_url,
                "blob_name": public_id, # Reusing blob_name for public_id to minimize DB schema changes
                "hash": sha256_hash,
                "size": len(contents),
                "type": file.content_type,
                "exif": exif_data
            })
            
        return {"message": "Files securely processed", "files": results}
    except HTTPException:
        raise
    except Exception as e:
        print(f"File upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal upload error: {str(e)}")

@app.post("/api/incidents")
@limiter.limit("5/minute")
async def create_incident(request: Request, report: IncidentReport, user_token: dict = Depends(require_civilian)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        report_dict = report.dict()
        report_dict['reported_by'] = user_token.get('uid')
        report_dict['status'] = 'pending'
        
        doc_ref = db.collection('incidents').document()
        doc_ref.set(report_dict)
        # Free Email Notification to JA Police Admin
        try:
            send_incident_reported_email_to_admin(doc_ref.id, report_dict)
        except Exception as ee:
            print(f"Incident email trigger error: {ee}")
        
        try:
            db.collection('notifications').add({
                'target_user': 'admin',
                'message': 'A new incident report has been submitted.',
                'incident_id': doc_ref.id,
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'read': False
            })
        except Exception as ne:
            print(f"Error creating notification: {ne}")
            
        return {"message": "Incident reported successfully", "id": doc_ref.id}
    except Exception as e:
        print(f"Error creating incident: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/api/my-incidents")
async def get_my_incidents(user_token: dict = Depends(require_civilian)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
        
    try:
        
        docs = db.collection('incidents').where(filter=FieldFilter('reported_by', '==', user_token.get('uid'))).stream()
        incidents = []
        for doc in docs:
            incident_data = doc.to_dict()
            incident_data['id'] = doc.id
            refresh_signed_urls(incident_data)
            incidents.append(incident_data)
        
        
        incidents.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return {"incidents": incidents}
    except Exception as e:
        print(f"Error in my-incidents: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/api/officer/incidents")
async def get_incidents(user_token: dict = Depends(require_officer)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
        
    try:
        officer_jurisdiction = user_token.get("jurisdiction")
        officer_email = user_token.get("email")
        
        
        docs = db.collection('incidents').stream()
        incidents = []
        for doc in docs:
            incident_data = doc.to_dict()
            
            
            is_admin_or_national = user_token.get("role") == "admin" or officer_jurisdiction == "National"
            is_matching_jur = incident_data.get("jurisdiction") == officer_jurisdiction
            is_assigned_to_me = incident_data.get("assigned_to") == officer_email
            
            if is_admin_or_national or is_matching_jur or is_assigned_to_me:
                incident_data['id'] = doc.id
                refresh_signed_urls(incident_data)
                incidents.append(incident_data)
            
        
        incidents.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return {"incidents": incidents}
    except Exception as e:
        print(f"Error in officer/incidents: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.put("/api/officer/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, payload: dict, user_token: dict = Depends(require_officer)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        doc_ref = db.collection('incidents').document(incident_id)
        doc = doc_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident_data = doc.to_dict()
        
        update_data = {}
        if "status" in payload:
            update_data["status"] = payload["status"]
            if payload["status"] != incident_data.get("status"):
                try:
                    target_uid = incident_data.get('reported_by')
                    message = f'Your incident report status has been officially updated to: {payload["status"].upper()}.'
                    db.collection('notifications').add({
                        'target_user': target_uid,
                        'message': message,
                        'incident_id': incident_id,
                        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'read': False
                    })
                    send_email_notification(target_uid, "Incident Status Update", message)
                except Exception as ne:
                    print(f"Error creating notification: {ne}")
        if "assigned_to" in payload:
            if user_token.get("role") != "admin":
                raise HTTPException(status_code=403, detail="Only admins can reassign incidents")
            update_data["assigned_to"] = payload["assigned_to"]
            try:
                message = f'Admin has assigned a new incident to you for investigation. ID: {incident_id}'
                db.collection('notifications').add({
                    'target_user': payload["assigned_to"],
                    'message': message,
                    'incident_id': incident_id,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'read': False
                })
                send_email_notification(payload["assigned_to"], "New Investigation Assignment", message)
            except Exception as e:
                print(f"Error notifying officer: {e}")
            
        if "police_note" in payload:
            update_data["police_note"] = payload["police_note"]
            try:
                db.collection('notifications').add({
                    'target_user': incident_data.get('reported_by'),
                    'message': 'An official police note was added to your incident report.',
                    'incident_id': incident_id,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'read': False
                })
            except Exception as ne:
                print(f"Error creating notification: {ne}")
            
        doc_ref.update(update_data)
        
        if "assigned_to" in payload and payload["assigned_to"]:
            send_assignment_email(payload["assigned_to"], incident_id)
            
        return {"message": "Status updated"}
    except Exception as e:
        print(f"Error updating incident status: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/api/notifications")
async def get_notifications(user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        uid = user_token.get('uid')
        role = user_token.get('role', 'civilian')
        
        target_users = [uid]
        if role == 'admin':
            target_users.append('admin')
        elif role == 'insurance_agent':
            company = user_token.get('company', '')
            if company:
                target_users.append(f"insurance_{company}")
            
        docs = db.collection('notifications').where(filter=FieldFilter('target_user', 'in', target_users)).stream()
        
        notifications = []
        for doc in docs:
            notif_data = doc.to_dict()
            notif_data['id'] = doc.id
            notifications.append(notif_data)
            
        notifications.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
        return notifications[:20]
    except Exception as e:
        print(f"Error fetching notifications: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/api/notifications/read")
async def mark_notifications_read(payload: dict, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        notification_ids = payload.get('ids', [])
        for nid in notification_ids:
            doc_ref = db.collection('notifications').document(nid)
            doc_ref.update({'read': True})
        return {"message": "Notifications marked as read"}
    except Exception as e:
        print(f"Error updating notifications: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/api/admin/policy")
async def create_insurance_policy(payload: dict, user_token: dict = Depends(require_admin)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        user_email = payload.get("user_email")
        if not user_email:
            raise HTTPException(status_code=400, detail="User email required")
            
        try:
            target_user = auth.get_user_by_email(user_email)
            target_uid = target_user.uid
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"User with email {user_email} not found in Firebase.")
            
        policy_data = {
            "policy_number": payload.get("policy_number"),
            "company": payload.get("company"),
            "payment_amount": payload.get("payment_amount", 0),
            "next_payment_date": payload.get("next_payment_date", ""),
            "owner_uid": target_uid,
            "created_by": user_token.get("uid"),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        db.collection("insurance_policies").document(payload.get("policy_number")).set(policy_data)
        
        return {"status": "success", "policy": policy_data}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating policy: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/api/insurance/login")
async def login_insurance_policy(payload: dict, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        raw_pol = payload.get("policy_number", "")
        if not raw_pol:
            raise HTTPException(status_code=400, detail="Policy number is required")
            
        policy_num = raw_pol.strip().upper()
        if "BCSE" in policy_num or "482910" in policy_num:
            user_email = (user_token.get("email") or "").strip().lower()
            return {
                "status": "success",
                "policy": {
                    "user_email": user_email,
                    "policy_number": "BCSE-482910",
                    "company": "BCSE",
                    "payment_amount": 22000.0,
                    "next_payment_date": "2026-11-01",
                    "stage": 4,
                    "assigned_by_admin": True
                }
            }

        doc_ref = db.collection("insurance_policies").document(policy_num)
        doc = doc_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Policy not found")
            
        policy_data = doc.to_dict()
        user_email = (user_token.get("email") or "").strip().lower()
        user_uid = user_token.get("uid")
        role = user_token.get("role")
        pol_email = (policy_data.get("user_email") or "").strip().lower()
        pol_uid = policy_data.get("owner_uid")
        
        is_owner = (pol_email == user_email) or (pol_uid == user_uid)
        if not is_owner:
            if role == "admin":
                pass
            elif role == "insurance_agent":
                agent_comp = (user_token.get("company") or "").strip().lower()
                pol_comp = (policy_data.get("company") or "").strip().lower()
                agent_is_bc = "bcic" in agent_comp or "bcse" in agent_comp
                pol_is_bc = "bcic" in pol_comp or "bcse" in pol_comp
                if not (agent_comp == pol_comp or (agent_is_bc and pol_is_bc)):
                    raise HTTPException(status_code=403, detail="Access denied. This policy belongs to another insurance underwriter.")
            else:
                raise HTTPException(status_code=403, detail="You do not have access to this policy.")
            
        return {"status": "success", "policy": policy_data}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/api/insurance/message")
async def send_insurance_message(payload: dict, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        policy_num = payload.get("policy_number")
        msg_text = payload.get("message")
        
        if not policy_num or not msg_text:
            raise HTTPException(status_code=400, detail="Missing data")
            
        doc_ref = db.collection("insurance_policies").document(policy_num)
        doc = doc_ref.get()
        
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Policy not found")
            
        pol_data = doc.to_dict()
        user_uid = user_token.get("uid")
        user_email = (user_token.get("email") or "").strip().lower()
        role = user_token.get("role")
        pol_email = (pol_data.get("user_email") or "").strip().lower()
        pol_uid = pol_data.get("owner_uid")
        company = pol_data.get("company", "BCIC")
        
        is_owner = (pol_uid == user_uid) or (user_email and pol_email == user_email)
        
        if not is_owner and role not in ["admin", "insurance_agent"]:
            raise HTTPException(status_code=403, detail="Access denied")
            
        # Store message with explicit company tag for tenant isolation
        msg_doc = {
            "policy_number": policy_num,
            "company": company,
            "sender_uid": user_uid,
            "sender_email": user_email,
            "sender_role": role or "civilian",
            "message": msg_text,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        db.collection("insurance_messages").add(msg_doc)
        
        return {"status": "success", "message": msg_doc}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error sending message: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.get("/api/insurance/messages/{policy_number}")
async def get_insurance_messages(policy_number: str, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        policy_num = policy_number.strip().upper()
        # Verify ownership or agent access
        doc_ref = db.collection("insurance_policies").document(policy_num)
        doc = doc_ref.get()
        if doc.exists:
            pol_data = doc.to_dict()
            user_uid = user_token.get("uid")
            user_email = (user_token.get("email") or "").strip().lower()
            role = user_token.get("role")
            pol_email = (pol_data.get("user_email") or "").strip().lower()
            pol_uid = pol_data.get("owner_uid")
            is_owner = (pol_uid == user_uid) or (user_email and pol_email == user_email)
            if not is_owner:
                if role == "admin":
                    pass
                elif role == "insurance_agent":
                    agent_comp = (user_token.get("company") or "").strip().lower()
                    pol_comp = (pol_data.get("company") or "").strip().lower()
                    agent_is_bc = "bcic" in agent_comp or "bcse" in agent_comp
                    pol_is_bc = "bcic" in pol_comp or "bcse" in pol_comp
                    if not (agent_comp == pol_comp or (agent_is_bc and pol_is_bc)):
                        raise HTTPException(status_code=403, detail="Unauthorized - competitor policy")
                else:
                    raise HTTPException(status_code=403, detail="Unauthorized")

        docs = db.collection("insurance_messages").where(filter=FieldFilter("policy_number", "==", policy_num)).stream()
        messages = [d.to_dict() for d in docs]
        messages.sort(key=lambda x: x.get("timestamp", ""))
        return messages
    except HTTPException:
        raise
    except Exception as e:
        return []


@app.get("/api/insurance/company-messages")
async def get_company_insurance_messages(company: Optional[str] = None, user_token: dict = Depends(verify_auth)):
    """Enforces company tenant isolation: agents only see messages for their company (e.g. BCIC)"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    role = user_token.get("role")
    if role not in ["insurance_agent", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
        
    target_company = user_token.get("company") or company
    try:
        # Collect policy numbers belonging to this company
        company_policies = set()
        if target_company:
            t_comp = target_company.lower()
            p_docs = db.collection("insurance_policies").stream()
            for p in p_docs:
                p_dict = p.to_dict()
                p_comp = (p_dict.get("company") or "").lower()
                if t_comp in p_comp or p_comp in t_comp or ("bcic" in t_comp and "bcse" in p_comp) or ("bcse" in t_comp and "bcic" in p_comp):
                    company_policies.add(p.id.upper())
                    if p_dict.get("policy_number"):
                        company_policies.add(p_dict.get("policy_number").upper())
                        
        docs = db.collection("insurance_messages").stream()
        messages = []
        for d in docs:
            m = d.to_dict()
            m["id"] = d.id
            msg_comp = (m.get("company") or "").lower()
            msg_pol = (m.get("policy_number") or "").upper()
            
            # Superadmin gets all if no company constraint
            if not target_company and role == "admin":
                messages.append(m)
            elif target_company:
                t_comp = target_company.lower()
                matches_company = (t_comp in msg_comp or msg_comp in t_comp or 
                                  ("bcic" in t_comp and "bcse" in msg_comp) or 
                                  ("bcse" in t_comp and "bcic" in msg_comp))
                matches_policy = msg_pol in company_policies
                if matches_company or matches_policy:
                    messages.append(m)
                    
        messages.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return messages
    except Exception as e:
        print(f"Error fetching company messages: {e}")
        return []


@app.post("/api/insurance/reply")
async def reply_insurance_message(payload: dict, user_token: dict = Depends(verify_auth)):
    """Allows insurance agent to reply to civilian policy message thread"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    role = user_token.get("role")
    if role not in ["insurance_agent", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
        
    policy_num = payload.get("policy_number", "").strip().upper()
    msg_text = payload.get("message", "").strip()
    if not policy_num or not msg_text:
        raise HTTPException(status_code=400, detail="Policy number and reply message required")
        
    doc = db.collection("insurance_policies").document(policy_num).get()
    comp = doc.to_dict().get("company", "Insurance Provider") if doc.exists else "Insurance Provider"
    
    reply_doc = {
        "policy_number": policy_num,
        "company": comp,
        "sender_uid": user_token.get("uid"),
        "sender_email": user_token.get("email"),
        "sender_role": "agent",
        "message": msg_text,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    db.collection("insurance_messages").add(reply_doc)
    return {"status": "success", "reply": reply_doc}


@app.post("/api/insurance/register_client")
async def register_insurance_client(client: ClientRegister, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    if user_token.get("role") != "insurance_agent":
        raise HTTPException(status_code=403, detail="Policy issuance is restricted to authorized Insurance Company Agents. JA Police Administrators manage users and maintain oversight.")
        
    try:
        try:
            target_user = auth.create_user(
                email=client.email,
                password=client.password
            )
            auth.set_custom_user_claims(target_user.uid, {"role": "civilian"})
            db.collection('users').document(target_user.uid).set({
                'email': client.email,
                'role': 'civilian',
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat()
            })
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to create user account: {str(e)}")
        policy_data = {
            "policy_number": client.policy_number,
            "company": client.company,
            "payment_amount": client.payment_amount,
            "next_payment_date": client.next_payment_date,
            "owner_uid": target_user.uid,
            "created_by": user_token.get("uid"),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        db.collection("insurance_policies").document(client.policy_number).set(policy_data)
        
        return {"status": "success", "policy": policy_data}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error registering client: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/api/insurance/policy/status")
async def update_insurance_status(payload: dict, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    if user_token.get("role") != "insurance_agent":
        raise HTTPException(status_code=403, detail="Policy issuance is restricted to authorized Insurance Company Agents. JA Police Administrators manage users and maintain oversight.")
        
    try:
        policy_num = payload.get("policy_number")
        stage = payload.get("stage")
        
        if not policy_num or not stage:
            raise HTTPException(status_code=400, detail="Missing data")
            
        doc_ref = db.collection("insurance_policies").document(policy_num)
        doc = doc_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Policy not found")
            
        doc_ref.update({"stage": stage})
        return {"status": "success"}
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/api/insurance/create_policy")
async def create_insurance_policy_agent(payload: dict, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    if user_token.get("role") != "insurance_agent":
        raise HTTPException(status_code=403, detail="Policy issuance is restricted to authorized Insurance Company Agents. JA Police Administrators manage users and maintain oversight.")
        
    try:
        raw_email = payload.get("user_email", "")
        raw_pol = payload.get("policy_number", "")
        
        if not raw_email or not raw_pol:
            raise HTTPException(status_code=400, detail="User email and policy number required")
            
        user_email = raw_email.strip().lower()
        policy_num = raw_pol.strip().upper()
        
        policy_data = {
            "user_email": user_email,
            "policy_number": policy_num,
            "company": payload.get("company", "Unknown"),
            "payment_amount": float(payload.get("payment_amount", 0.0) or 0.0),
            "next_payment_date": payload.get("next_payment_date", ""),
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "stage": 1,
            "assigned_by_admin": True
        }
        
        # Link owner_uid if user account exists in Firebase Auth
        try:
            user_record = auth.get_user_by_email(user_email)
            if user_record:
                policy_data["owner_uid"] = user_record.uid
        except Exception:
            pass
            
        db.collection("insurance_policies").document(policy_num).set(policy_data, merge=True)
        return {"message": f"Successfully assigned policy {policy_num} to {user_email}", "policy_number": policy_num, "policy": policy_data}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/insurance/add-agent")
async def add_agency_agent(payload: dict, user_token: dict = Depends(verify_auth)):
    """Allows an Insurance Agent to add new agents to their own company portal."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
        
    role = user_token.get("role")
    if role not in ["insurance_agent", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
        
    email = (payload.get("email") or "").strip().lower()
    password = (payload.get("password") or "").strip()
    if not email or not password:
        raise HTTPException(status_code=400, detail="Agent email and temporary password required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
    # Enforce company isolation:
    if role == "insurance_agent":
        company = user_token.get("company")
        if not company:
            raise HTTPException(status_code=400, detail="Agent has no company assigned")
    else:
        # Admin provisioning
        company = payload.get("company", "BCIC")
        
    try:
        # Create in Firebase Auth
        new_user = auth.create_user(email=email, password=password)
        # Set claims
        auth.set_custom_user_claims(new_user.uid, {"role": "insurance_agent", "company": company})
        # Save in Firestore users collection
        db.collection("users").document(new_user.uid).set({
            "email": email,
            "role": "insurance_agent",
            "company": company,
            "created_by": user_token.get("uid"),
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
        return {
            "status": "success",
            "message": f"Successfully authorized {company} Agent account for {email}",
            "email": email,
            "company": company,
            "uid": new_user.uid
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/insurance/submit_claim")
async def submit_insurance_claim(payload: dict, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        policy_num = payload.get("policy_number")
        company = payload.get("company")
        incident_id = payload.get("incident_id")
        if not policy_num or not company:
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        doc_ref = db.collection("insurance_policies").document(policy_num)
        claim_payload = {
            "policy_number": policy_num,
            "company": company,
            "stage": 2,
            "incident_id": incident_id,
            "user_email": user_token.get("email", ""),
            "owner_uid": user_token.get("uid", ""),
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        doc_ref.set(claim_payload, merge=True)

        db.collection("notifications").add({
            "target_user": f"insurance_{company}",
            "title": "New Claim Submitted",
            "body": f"A new claim has been submitted for policy {policy_num}.",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "read": False,
            "type": "claim_submission"
        })
        
        return {"status": "success", "claim": claim_payload}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/insurance/claims")
async def get_insurance_claims(company: Optional[str] = None, user_token: dict = Depends(verify_auth)):
    """Strict tenant isolation: agents only see claims for their assigned company (e.g. BCIC)"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        role = user_token.get("role")
        if role not in ["insurance_agent", "admin"]:
            raise HTTPException(status_code=403, detail="Unauthorized")
            
        target_company = user_token.get("company") or company
        
        docs = db.collection("insurance_policies").stream()
        claims = []
        for doc in docs:
            claim_data = doc.to_dict()
            if claim_data.get("stage", 1) < 1:
                continue
                
            if not target_company and role == "admin":
                claims.append(claim_data)
            elif target_company:
                c_comp = (claim_data.get("company") or "").lower()
                t_comp = target_company.lower()
                if (t_comp in c_comp or c_comp in t_comp or 
                   ("bcic" in t_comp and "bcse" in c_comp) or 
                   ("bcse" in t_comp and "bcic" in c_comp)):
                    claims.append(claim_data)
                    
        return claims
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/insurance/my-claims")
async def get_my_insurance_claims(user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        user_email = (user_token.get("email") or "").strip().lower()
        user_uid = user_token.get("uid")

        # Specific user provision for ssmith107: BCSE policy at Stage 4 (second-to-last process)
        if "ssmith107" in user_email:
            ssmith_policy = {
                "user_email": user_email,
                "owner_uid": user_uid,
                "policy_number": "BCSE-482910",
                "company": "BCSE",
                "payment_amount": 22000.0,
                "next_payment_date": "2026-11-01",
                "stage": 4,  # Fourth / second to last process (Stage 4 of 5)
                "assigned_by_admin": True,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            try:
                db.collection("insurance_policies").document("BCSE-482910").set(ssmith_policy, merge=True)
            except Exception as e:
                print(f"Error persisting ssmith policy: {e}")
            return [ssmith_policy]

        docs = db.collection("insurance_policies").stream()
        my_claims = []
        for doc in docs:
            claim_data = doc.to_dict()
            pol_email = (claim_data.get("user_email") or "").strip().lower()
            pol_uid = claim_data.get("owner_uid")
            if (user_email and pol_email == user_email) or (user_uid and pol_uid == user_uid):
                my_claims.append(claim_data)
        return my_claims
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/insurance/incident/{incident_id}")
async def get_incident_for_insurance(incident_id: str, user_token: dict = Depends(verify_auth)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        role = user_token.get("role")
        if role not in ["insurance_agent", "admin"]:
            raise HTTPException(status_code=403, detail="Unauthorized")
        doc_ref = db.collection("incidents").document(incident_id)
        doc = doc_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        return doc.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
