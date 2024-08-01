from flask import Flask, redirect, url_for, render_template, request, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
# from oauthlib.oauth2 import WebApplicationClient
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
# import firebase_admin
# from firebase_admin import credentials, auth
import requests
import json
import os
from dotenv import load_dotenv

# # Initialize Firebase Admin SDK
# cred = credentials.Certificate('credentials.json')
# firebase_admin.initialize_app(cred)

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'
oauth=OAuth(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

load_dotenv()
# OAuth 2 client setup
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")
# client = WebApplicationClient(GOOGLE_CLIENT_ID)
print(GOOGLE_CLIENT_ID)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=GOOGLE_DISCOVERY_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# User class for Flask-Login
class User:
    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(user_id):
    user = auth.get_user(user_id)
    if user:
        return User(user_id, user.display_name, user.email)
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return f'Hello, {current_user.name}!'
    return 'You are not logged in.'

@app.route('/login')
def login():
    redirect_uri=url_for('callback',_external=True)
    session["nonce"]=generate_token()
    return oauth.google.authorize_redirect(redirect_uri,nonce=session["nonce"])
    
    
    # google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    # authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    # request_uri = client.prepare_request_uri(
    # authorization_endpoint,
    # redirect_uri="https://abcd1234.ngrok.io/login/callback",
    # scope=["openid", "email", "profile"],
# )
#     print(request_uri)
#     return redirect(request_uri)


@app.route("/login/callback")
def callback():
    token=oauth.google.authorize_access_token()
    google_user=oauth.google.parse_id_token(token,nonce=session["nonce"])
    return google_user['email']
    
    
    # code = request.args.get("code")
    # google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    # token_endpoint = google_provider_cfg["token_endpoint"]

    # token_url, headers, body = client.prepare_token_request(
    #     token_endpoint,
    #     authorization_response=request.url,
    #     redirect_url=request.base_url,
    #     code=code
    # )
    # token_response = requests.post(
    #     token_url,
    #     headers=headers,
    #     data=body,
    #     auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    # )
    # client.parse_request_body_response(json.dumps(token_response.json()))

    # userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    # uri, headers, body = client.add_token(userinfo_endpoint)
    # userinfo_response = requests.get(uri, headers=headers, data=body)

    # userinfo = userinfo_response.json()
    # unique_id = userinfo["sub"]
    # users_name = userinfo["name"]
    # users_email = userinfo["email"]

    # user = User(unique_id, users_name, users_email)
    # login_user(user)

    # # Save device token and user info to Firebase
    # token = request.cookies.get('token')
    # auth.update_user(unique_id, email=users_email, display_name=users_name)
    # return redirect(url_for("index"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
