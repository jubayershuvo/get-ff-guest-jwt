"""
Flask API for Free Fire JWT Generation
Endpoint: /get_jwt?uid=&password=
"""

from flask import Flask, request, jsonify
import json
from datetime import datetime
import base64

from get_jwt import getJwt


app = Flask(__name__)

def decode_jwt_payload(jwt_token):
    """
    Decode JWT payload to extract expiry and other data
    """
    try:
        # Split JWT and get payload (second part)
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += '=' * padding
            
            # Decode base64
            decoded = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(decoded)
            
            return payload
    except Exception as e:
        print(f"Error decoding JWT: {e}")
    return None

def format_expiry(exp_timestamp):
    """
    Format expiry timestamp to readable datetime
    """
    try:
        if exp_timestamp:
            dt = datetime.fromtimestamp(exp_timestamp)
            return {
                "timestamp": exp_timestamp,
                "datetime": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "timezone": "UTC"
            }
    except Exception as e:
        print(f"Error formatting expiry: {e}")
    return None

@app.route('/get_jwt', methods=['GET'])
def get_jwt_endpoint():
    """
    API Endpoint to get JWT from UID, Password
    
    Query Parameters:
    - uid: Account UID (required)
    - password: Account password (required)
    
    Example:
    /get_jwt?uid=4754356819&password=1589073FEF11EA9A10FDB0A2B6C05C4337C95C6503DF2EAF25E5AEF37EAA4034
    """
    
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid:
        return jsonify({
            "success": False,
            "error": "Missing required parameter: uid",
            "message": "Please provide uid parameter"
        }), 400
    
    if not password:
        return jsonify({
            "success": False,
            "error": "Missing required parameter: password",
            "message": "Please provide password parameter"
        }), 400
    
    try:
        result = getJwt(uid, password)
        print(result)
        
        # Add timestamp to response
        result["timestamp"] = datetime.now().isoformat()
        
        # Extract and add expiry information if JWT exists
        if result.get("success") and result.get("jwt_token"):
            jwt_payload = decode_jwt_payload(result["jwt_token"])
            
            if jwt_payload:
                # Extract expiry
                exp = jwt_payload.get("exp")
                if exp:
                    result["expiry"] = format_expiry(exp)
                    result["external_id"] = jwt_payload.get("external_id")
                    result["signature_md5"] = jwt_payload.get("signature_md5")
                
                # Add all JWT payload data to response
                result["jwt_payload"] = jwt_payload
        
        if result.get("success"):
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Internal server error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500


@app.route('/decode_jwt', methods=['POST', 'GET'])
def decode_jwt_endpoint():
    """
    Decode JWT token and extract expiry
    
    For GET: /decode_jwt?token=jwt_token_here
    For POST: {"token": "jwt_token_here"}
    """
    
    if request.method == 'GET':
        jwt_token = request.args.get('token')
    else:
        data = request.get_json()
        jwt_token = data.get('token') if data else None
    
    if not jwt_token:
        return jsonify({
            "success": False,
            "error": "Missing token parameter"
        }), 400
    
    try:
        payload = decode_jwt_payload(jwt_token)
        
        if payload:
            exp = payload.get("exp")
            expiry_info = format_expiry(exp) if exp else None
            
            return jsonify({
                "success": True,
                "payload": payload,
                "expiry": expiry_info,
                "external_id": payload.get("external_id"),
                "signature_md5": payload.get("signature_md5"),
                "decoded_at": datetime.now().isoformat()
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "Failed to decode JWT"
            }), 400
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Free Fire JWT Generator API",
        "timestamp": datetime.now().isoformat()
    }), 200


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "service": "Free Fire JWT Generator API",
        "version": "1.0.0",
        "endpoints": {
            "/get_jwt": {
                "method": "GET",
                "parameters": {
                    "uid": "required - Account UID",
                    "password": "required - Account password", 
                },
                "example": "/get_jwt?uid=4754356819&password=your_password"
            },
            "/decode_jwt": {
                "method": "GET or POST",
                "parameters": {
                    "token": "required - JWT token to decode"
                },
                "example": "/decode_jwt?token=eyJhbGciOiJIUzI1NiIs..."
            },
            "/health": {
                "method": "GET",
                "description": "Health check endpoint"
            }
        }
    }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5080, debug=True)