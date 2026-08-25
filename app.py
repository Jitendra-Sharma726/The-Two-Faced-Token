from flask import Flask, request, jsonify
import jwt
import os
from jwt.algorithms import HMACAlgorithm

# =======================================================
# VULNERABILITY SIMULATION: MONKEY PATCHING
# Because we are using a modern Python environment, we must
# force the server to act like an older, vulnerable version 
# of PyJWT that blindly trusted HMAC asymmetric keys.
# =======================================================
def bypass_security_check(self, key):
    if isinstance(key, str):
        return key.encode('utf-8')
    return key

HMACAlgorithm.prepare_key = bypass_security_check
# =======================================================

app = Flask(__name__)

# Load keys
with open('private.pem', 'r') as f:
    PRIVATE_KEY = f.read()
    
with open('public.pem', 'r') as f:
    PUBLIC_KEY = f.read()

@app.route('/')
def index():
    return "Microservice Online. Endpoints: /token, /vault"

@app.route('/token')
def get_token():
    """Issues a standard, unprivileged token using RS256."""
    payload = {
        "username": "guest_user",
        "role": "user"
    }
    # Properly signed with the private key
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return jsonify({"token": token, "message": "Standard user token issued."})

@app.route('/vault')
def secure_vault():
    """Restricted endpoint requiring an Admin JWT."""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
        
    token = auth_header.split(" ")[1]

    try:
        # THE VULNERABILITY:
        # The backend extracts the 'alg' from the unverified header.
        # It then uses the PUBLIC_KEY to verify the token, but allows BOTH RS256 and HS256.
        unverified_header = jwt.get_unverified_header(token)
        alg = unverified_header.get('alg')
        
        decoded_payload = jwt.decode(token, PUBLIC_KEY, algorithms=[alg])
        
        # Check for Privilege Escalation
        if decoded_payload.get("role") == "admin":
            real_flag = os.environ.get('CTF_FLAG', 'CTF{4lg0_c0nfus10n_m4st3r_101}')
            return jsonify({"message": "ACCESS GRANTED", "flag": real_flag})
        else:
            return jsonify({"error": "Access Denied. Admin role required."}), 403

    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)


