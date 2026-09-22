import os
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "firebase-credentials.json"
cred = credentials.Certificate("firebase-credentials.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

try:
    docs = db.collection('incidents').where(filter=FieldFilter('reported_by', '==', 'test_uid')).order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
    for doc in docs:
        pass
    print("Success!")
except Exception as e:
    print(f"Error: {e}")
