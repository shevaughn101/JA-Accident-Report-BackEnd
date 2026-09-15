import os
import hashlib
import uuid
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from io import BytesIO
from datetime import timedelta
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import firebase_admin
from firebase_admin import credentials, firestore, auth, storage
from google.cloud.firestore_v1.base_query import FieldFilter
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from typing import List, Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded


limiter = Limiter(key_func=get_remote_address)


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
        firebase_admin.initialize_app(cred, {
            'storageBucket': 'incidentplatform.firebasestorage.app'
        })
    db = firestore.client()
    bucket = storage.bucket()
except Exception as e:
    print(f"Warning: Firebase Admin SDK initialization failed. Error: {e}")
    db = None
    bucket = None




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
    """Refreshes Signed URLs for any evidence containing a blob_name."""
    if not bucket: return
    
    for field in ['scenePhotos', 'statutoryDocs']:
        if field in incident_data and isinstance(incident_data[field], list):
            for file_obj in incident_data[field]:
                if 'blob_name' in file_obj:
                    
                    file_obj['url'] = f"https://ja-accident-report-backend.onrender.com/api/evidence/{file_obj['blob_name']}"

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




class IncidentReport(BaseModel):
    type: str
    location: str
    jurisdiction: str
    description: str
    timestamp: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    vehicleDetails: dict = {}
    involvedParties: list = []
    witnesses: list = []
    statutoryDocs: list = []
    scenePhotos: list = []

class OfficerCreate(BaseModel):
    email: EmailStr
    password: str
    jurisdiction: str

class RoleUpdate(BaseModel):
    role: str
    jurisdiction: str = "Unknown"





@app.post("/api/auth/verify")
async def verify_auth(token: dict = Depends(verify_firebase_token)):
    return {
        "role": token.get("role", "civilian"),
        "jurisdiction": token.get("jurisdiction", "Unknown")
    }

@app.post("/api/admin/officers")
async def create_officer(officer: OfficerCreate, admin_token: dict = Depends(require_admin)):
    try:
        user = auth.create_user(
            email=officer.email,
            password=officer.password,
            email_verified=True
        )
        auth.set_custom_user_claims(user.uid, {"role": "officer", "jurisdiction": officer.jurisdiction})
        return {"message": "Officer created successfully", "uid": user.uid}
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

@app.get("/api/evidence/{uid}/{filename}")
async def get_evidence(uid: str, filename: str, user_token: dict = Depends(require_officer)):
    """Internal proxy endpoint to fetch evidence securely, bypassing GCP IAM issues"""
    if not bucket:
        raise HTTPException(status_code=503, detail="Storage not configured")
    try:
        blob = bucket.blob(f"{uid}/{filename}")
        if not blob.exists():
            raise HTTPException(status_code=404, detail="Evidence not found")
            
        content = blob.download_as_bytes()
        
        
        content_type = "application/octet-stream"
        if filename.lower().endswith(".jpg") or filename.lower().endswith(".jpeg"):
            content_type = "image/jpeg"
        elif filename.lower().endswith(".png"):
            content_type = "image/png"
        elif filename.lower().endswith(".pdf"):
            content_type = "application/pdf"
            
        return Response(content=content, media_type=content_type)
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching evidence: {e}")
        raise HTTPException(status_code=500, detail="Failed to load evidence")

@app.post("/api/upload")
@limiter.limit("10/minute")
async def upload_files(
    request: Request,
    files: List[UploadFile] = File(...), 
    user_token: dict = Depends(require_civilian)
):
    if not bucket:
        raise HTTPException(status_code=503, detail="Storage not configured")
        
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
                
            
            unique_name = f"{user_token.get('uid')}/{uuid.uuid4()}_{file.filename}"
            blob = bucket.blob(unique_name)
            
            
            blob.upload_from_string(contents, content_type=file.content_type)
            
            
            proxy_url = f"https://ja-accident-report-backend.onrender.com/api/evidence/{unique_name}"
            
            results.append({
                "name": file.filename,
                "url": proxy_url,
                "blob_name": unique_name,
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
        
        update_data = {}
        if "status" in payload:
            update_data["status"] = payload["status"]
        if "assigned_to" in payload:
            if user_token.get("role") != "admin":
                raise HTTPException(status_code=403, detail="Only admins can reassign incidents")
            update_data["assigned_to"] = payload["assigned_to"]
            
        doc_ref.update(update_data)
        
        if "assigned_to" in payload and payload["assigned_to"]:
            send_assignment_email(payload["assigned_to"], incident_id)
            
        return {"message": "Status updated"}
    except Exception as e:
        print(f"Error updating incident status: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
