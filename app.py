from flask import Flask, request, jsonify
import asyncio
import aiohttp
import json
import os
import time
import threading
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import requests
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

TOKEN_ME_FILE = "token_me.json"
ME_JWT_FILE = "me.json"
JWT_API = "https://7ama-prv-jwt.vercel.app/token?uid={uid}&password={password}"
REFRESH_INTERVAL = 6 * 60 * 60  # 6 hours

# ====== JWT Fetcher ======
async def fetch_jwt(uid, password):
    tries = 0
    while tries < 5:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(JWT_API.format(uid=uid, password=password)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        token = data.get("token")
                        if token:
                            return token
                    else:
                        app.logger.warning(f"JWT fetch failed for UID {uid}, status: {resp.status}")
        except Exception as e:
            app.logger.error(f"Error fetching JWT for UID {uid}: {e}")
        tries += 1
        await asyncio.sleep(2)
    return None

async def refresh_all_jwts():
    if not os.path.exists(TOKEN_ME_FILE):
        app.logger.error("token_me.json not found!")
        return
    with open(TOKEN_ME_FILE, "r") as f:
        accounts = json.load(f)

    new_tokens = []
    for acc in accounts:
        token = await fetch_jwt(acc["uid"], acc["password"])
        if token:
            new_tokens.append({"token": token})
            app.logger.info(f"JWT generated for UID {acc['uid']}")
        else:
            app.logger.warning(f"Failed to generate JWT for UID {acc['uid']}")

    with open(ME_JWT_FILE, "w") as f:
        json.dump(new_tokens, f, indent=2)

def background_jwt_task():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        app.logger.info(f"Refreshing JWTs at {datetime.now()}")
        loop.run_until_complete(refresh_all_jwts())
        time.sleep(REFRESH_INTERVAL)

# ====== Load tokens ======
def load_tokens(server_name):
    try:
        if server_name == "me":
            with open(ME_JWT_FILE, "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

# ====== Encryption & Protobuf ======
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        if hasattr(message, 'ob_version'):
            message.ob_version = "OB48"
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    text = await response.text()
                    app.logger.error(f"Request failed: {response.status} -> {text}")
                    return None
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if not protobuf_message:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid:
            return None
        tokens = load_tokens(server_name)
        if not tokens:
            return None
        tasks = []
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        if hasattr(message, 'ob_version'):
            message.ob_version = "OB48"
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if not protobuf_data:
        return None
    return encrypt_message(protobuf_data)

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code != 200:
            return None
        items = like_count_pb2.Info()
        items.ParseFromString(response.content)
        return items
    except Exception as e:
        return None

# ====== /like Endpoint ======
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400
    try:
        tokens = load_tokens(server_name)
        if not tokens:
            raise Exception("Failed to load tokens.")
        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption of UID failed.")
        before = make_request(encrypted_uid, server_name, token)
        if not before:
            raise Exception("Failed to retrieve initial player info.")
        before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"
        asyncio.run(send_multiple_requests(uid, server_name, url))
        after = make_request(encrypted_uid, server_name, token)
        if not after:
            raise Exception("Failed to retrieve player info after like requests.")
        after_like = int(json.loads(MessageToJson(after)).get('AccountInfo', {}).get('Likes', 0))
        like_given = after_like - before_like
        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "status": 1 if like_given != 0 else 2
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    threading.Thread(target=background_jwt_task, daemon=True).start()
    app.run(debug=True, use_reloader=False)
