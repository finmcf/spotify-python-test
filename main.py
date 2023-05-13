from flask import Flask, request, redirect, render_template_string
import requests
import os
import base64
import hashlib
import urllib.parse

app = Flask(__name__)
app.debug = True

CLIENT_ID = 'ffd2b6481cb84901932381a5ba9e8554'
REDIRECT_URI = 'http://localhost:5173/callback'
VERIFIER = None

def generate_code_verifier(length):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8')[:length]

def generate_code_challenge(verifier):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(verifier.encode('utf-8'))
    challenge = base64.urlsafe_b64encode(sha256_hash.digest()).decode('utf-8')
    return challenge.replace('=', '')

@app.route('/')
def home():
    global VERIFIER
    VERIFIER = generate_code_verifier(128)
    challenge = generate_code_challenge(VERIFIER)

    auth_url = 'https://accounts.spotify.com/authorize'
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': 'user-read-private user-read-email',
        'code_challenge_method': 'S256',
        'code_challenge': challenge,
    }
    url = f"{auth_url}?{urllib.parse.urlencode(params)}"
    return redirect(url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    token_url = 'https://accounts.spotify.com/api/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'client_id': CLIENT_ID,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': VERIFIER,
    }
    response = requests.post(token_url, headers=headers, data=data)
    response.raise_for_status()
    access_token = response.json()['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get('https://api.spotify.com/v1/me', headers=headers)
    response.raise_for_status()
    profile = response.json()
    return render_template_string(open('templates/profile.html').read(), profile=profile)

if __name__ == '__main__':
    app.run(port=5173)
