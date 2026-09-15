import os
import firebase_admin
from firebase_admin import credentials, auth


cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "firebase-credentials.json")
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"Failed to initialize Firebase Admin SDK. Error: {e}")
    exit(1)

ADMIN_EMAIL = "contactshevaughn124@gmail.com"
ADMIN_PASSWORD = "AdminPass2026!"

def bootstrap_admin():
    try:
        
        user = auth.get_user_by_email(ADMIN_EMAIL)
        print(f"User {ADMIN_EMAIL} already exists. Updating password and role...")
        auth.update_user(user.uid, password=ADMIN_PASSWORD)
    except auth.UserNotFoundError:
        print(f"User {ADMIN_EMAIL} does not exist. Creating new user...")
        user = auth.create_user(
            email=ADMIN_EMAIL,
            password=ADMIN_PASSWORD,
            email_verified=True
        )
        print(f"Successfully created user {ADMIN_EMAIL} (UID: {user.uid}).")
    
    
    auth.set_custom_user_claims(user.uid, {"role": "admin"})
    print(f"Successfully assigned 'admin' custom claim to {ADMIN_EMAIL}.")
    
    
    user = auth.get_user_by_email(ADMIN_EMAIL)
    print(f"Verified Claims: {user.custom_claims}")

if __name__ == "__main__":
    bootstrap_admin()
