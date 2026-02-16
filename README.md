# Server-Demo





# install 
Download Python 3.14.3 

create a virtual environment using venv python -m venv .venv  

source .venv/bin/activate

pip install -r requirements.txt








# AI prompts Used
This tool only supports a JWT that uses the JWS Compact Serialization, which must have three base64url-encoded segments separated by two period ('.') characters as defined 

best way to set up kid  

write the flask app like A RESTful JWKS endpoint that serves the public keys in JWKS format.
Only serve keys that have not expired.
A /auth endpoint that returns an unexpired, signed JWT on a POST request.
If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry.

write a test case for the code



