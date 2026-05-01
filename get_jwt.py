"""
get_jwt.py - Get JWT from existing UID/Password via MajorLogin
"""

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import urllib3
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONSTANTS ====================
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)

REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","EU": "en","CIS": "ru","NA": "en","SAC": "es","BR": "pt"}
REGION_URLS = {"IND": "https://client.ind.freefiremobile.com","ID": "https://clientbp.ggblueshark.com","BR": "https://client.us.freefiremobile.com","ME": "https://clientbp.common.ggbluefox.com","VN": "https://clientbp.ggblueshark.com","TH": "https://clientbp.common.ggbluefox.com","CIS": "https://clientbp.ggblueshark.com","BD": "https://loginbp.ggblueshark.com","PK": "https://clientbp.ggblueshark.com","SG": "https://clientbp.ggblueshark.com","NA": "https://client.us.freefiremobile.com","SAC": "https://client.us.freefiremobile.com","EU": "https://clientbp.ggblueshark.com","TW": "https://clientbp.ggblueshark.com"}

# ==================== PROTOBUF FUNCTIONS ====================
def EnC_Vr(N):
    if N < 0: return b''
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    if isinstance(value, str):
        encoded_value = value.encode('utf-8')
    elif isinstance(value, bytes):
        encoded_value = value
    else:
        encoded_value = str(value).encode('utf-8')
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, (str, bytes)):
            packet.extend(CrEaTe_LenGTh(field, value))           
    return packet

# ==================== ENCRYPTION ====================
def encrypt_api(plain_text):
    """Encrypt API payload"""
    if isinstance(plain_text, str):
        plain_text = bytes.fromhex(plain_text)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text

def encode_string(original):
    keystream = [
        0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31,
        0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30
    ]
    encoded = ""
    for i in range(len(original)):
        orig_byte = ord(original[i])
        key_byte = keystream[i % len(keystream)]
        result_byte = orig_byte ^ key_byte
        encoded += chr(result_byte)
    return encoded

def to_unicode_escaped(s):
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)

# ==================== MAIN FUNCTIONS ====================

def get_access_token(uid, password):
    """Step 1: Get access_token from Garena"""
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
    }
    
    body = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": key,
        "client_id": "100067"
    }
    
    try:
        response = requests.post(url, headers=headers, data=body, timeout=15)
        if response.status_code == 200:
            data = response.json()
            open_id = data.get('open_id')
            access_token = data.get('access_token')
            return open_id, access_token
        else:
            print(f"[-] Token grant failed: {response.status_code}")
            return None, None
    except Exception as e:
        print(f"[-] Error getting access token: {e}")
        return None, None

def major_login(uid, password, region="BD"):
    """
    Step 2: Login to get JWT using existing UID/Password
    """
    print(f"[*] Getting access token for UID {uid}...")
    open_id, access_token = get_access_token(uid, password)
    
    if not open_id or not access_token:
        return {"success": False, "message": "Failed to get access_token"}
    
    print(f"[+] Access token obtained")
    print(f"[*] Performing MajorLogin...")
    
    lang = REGION_LANG.get(region, "en")
    lang_b = lang.encode('ascii')
    
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com",
        "ReleaseVersion": "OB53",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }
    
    # Login Payload Template
    payload = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.123.10B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_b + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    
    # Replace placeholders
    data = payload
    data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
    data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
    
    # Encrypt
    encrypted = encrypt_api(data.hex())
    Final_Payload = encrypted


    
    url = REGION_URLS[region]+'/MajorLogin'
    print(f"[*] Sending MajorLogin request to {url}...")
    
    try:
        response = requests.post(url, headers=headers, data=Final_Payload, verify=False, timeout=15)
        
        if response.status_code == 200:
            # Extract JWT from response
            response_text = response.text
            
            if "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ" in response_text:
                start_idx = response_text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ")
                jwt_token = response_text[start_idx:]
                
                # Trim to valid JWT
                dot_positions = [i for i, c in enumerate(jwt_token) if c == '.']
                if len(dot_positions) >= 2:
                    jwt_token = jwt_token[:dot_positions[1] + 44]
                    
                    result = {
                        "success": True,
                        "jwt_token": jwt_token,
                        "uid": uid,
                        "password": password,
                        "open_id": open_id,
                        "access_token": access_token,
                        "region": region
                    }
                    
                    # Decode JWT to get details
                    try:
                        payload_b64 = jwt_token.split('.')[1]
                        padding = 4 - (len(payload_b64) % 4)
                        if padding != 4:
                            payload_b64 += '=' * padding
                        decoded = json.loads(base64.urlsafe_b64decode(payload_b64))
                        result["external_id"] = decoded.get("external_id")
                        result["signature_md5"] = decoded.get("signature_md5")
                    except:
                        pass
                    
                    print(f"[+] JWT obtained successfully!")
                    return result
            else:
                return {"success": False, "message": "JWT not found in response"}
        else:
            return {"success": False, "message": f"MajorLogin failed: {response.status_code}"}
            
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}


def getJwt(uid, password, region="BD"):
    """
    Get JWT from existing UID and Password
    
    Parameters:
    - uid: Account UID (e.g., "4754356819")
    - password: Account password
    - region: Server region (BD, IND, BR, US, etc.)
    
    Returns:
    - Dictionary with JWT token and account info
    """
    print(f"\n{'='*50}")
    print(f"Getting JWT for UID: {uid}")
    print(f"Region: {region}")
    print(f"{'='*50}\n")
    
    result = major_login(uid, password, region)
    
    if result["success"]:
        print(f"\n✅ SUCCESS!")
    else:
        print(f"\n❌ FAILED: {result['message']}")
    
    return result

