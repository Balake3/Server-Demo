from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta
import base64
import hashlib
import jwt

app = Flask(__name__)

def to_base64url(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")

def generate_rsa_keypair(expiry_minutes=60):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    n_b64 = to_base64url(public_numbers.n)
    e_b64 = to_base64url(public_numbers.e)

    # Thumbprint for kid
    thumbprint = f'{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}'.encode()
    kid = base64.urlsafe_b64encode(hashlib.sha256(thumbprint).digest()).rstrip(b"=").decode("utf-8")
    now = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(minutes=expiry_minutes)

    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": n_b64,
        "e": e_b64,
        "exp": int(expires_at.timestamp())
    }

    return {
        "private_key": private_key,
        "public_key": public_key,
        "jwk": jwk,
        "expires_at": expires_at
    }


key_store = [
    generate_rsa_keypair(expiry_minutes=60),   # valid key
    generate_rsa_keypair(expiry_minutes=-60)   # expired key
]


@app.route("/jwks")
def jwks():
    now = datetime.now(tz=timezone.utc)
    jwks_keys = [
        k["jwk"] for k in key_store if k["expires_at"] > now
    ]
    return jsonify({"keys": jwks_keys})


@app.route("/auth", methods=["POST"])
def auth():
    expired_requested = request.args.get("expired", "false").lower() == "true"
    now = datetime.now(tz=timezone.utc)

    if expired_requested:
        # Get an expired key, or fall back to first key if none exist
        key_data = next((k for k in key_store if k["expires_at"] <= now), key_store[0])
        exp_time = now - timedelta(hours=1)
    else:
        # Get a valid (non-expired) key
        key_data = next((k for k in key_store if k["expires_at"] > now), None)
        if not key_data:
            return jsonify({"error": "No valid keys available"}), 500

        exp_time = now + timedelta(hours=1)

    payload = {
        "name": "Test",
        "iat": int(now.timestamp()),
        "exp": int(exp_time.timestamp())
    }

    token = jwt.encode(
        payload,
        key_data["private_key"],
        algorithm="RS256",
        headers={"kid": key_data["jwk"]["kid"], "typ": "JWT"}
    )

    return jsonify({"token": token})



if __name__ == "__main__":
    app.run(port=8080)

# Ai prompts used
 # This tool only supports a JWT that uses the JWS Compact Serialization, which must have three base64url-encoded segments separated by two period ('.') characters as defined
# best way to set up kid
 # write the flask app so it does A RESTful JWKS endpoint that serves the public keys
    #write a test file
  #fix failed to extract response via extractor function: invalid TTP status code: 404
