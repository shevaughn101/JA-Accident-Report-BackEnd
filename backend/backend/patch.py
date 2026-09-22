import re

with open('main.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Update imports
content = content.replace('from pydantic import BaseModel, EmailStr', 
'''import html
import re
from pydantic import BaseModel, EmailStr, Field, field_validator''')

# Replace models
old_models = '''class IncidentReport(BaseModel):
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
    jurisdiction: str = "Unknown"'''

new_models = '''def sanitize_string(v: str) -> str:
    if not isinstance(v, str):
        return v
    # Reject obvious injection payloads
    malicious_patterns = [
        r'sleep\s*\(',
        r'cat\s+/etc/',
        r'\.\./\.\./',
        r'DBMS_SESSION\.SLEEP',
        r'java\.lang\.Thread\.sleep',
        r'(?i)select.*?from',
        r'(?i)union.*?select'
    ]
    for pattern in malicious_patterns:
        if re.search(pattern, v, re.IGNORECASE):
            raise ValueError("Invalid input detected")
    # Escape HTML to prevent XSS
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

    @field_validator('type', 'location', 'jurisdiction', 'description', 'timestamp', mode='before')
    @classmethod
    def sanitize_strings(cls, v):
        return sanitize_string(v)

class OfficerCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)
    jurisdiction: str = Field(..., max_length=100)

    @field_validator('jurisdiction', mode='before')
    @classmethod
    def sanitize_jurisdiction(cls, v):
        return sanitize_string(v)

class RoleUpdate(BaseModel):
    role: str = Field(..., max_length=50)
    jurisdiction: str = Field("Unknown", max_length=100)

    @field_validator('role', 'jurisdiction', mode='before')
    @classmethod
    def sanitize_role(cls, v):
        return sanitize_string(v)'''

content = content.replace(old_models, new_models)

with open('main.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Patched main.py")
