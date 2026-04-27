from flask import Flask, request, jsonify
import csv
import hashlib
import base64

app = Flask(__name__)

HASH_FILE = "storedhash.csv"

def clean(value):
    return value.strip() if isinstance(value, str) else ""

def custom_hash_hex(account_num, password):
    combined = (password + str(account_num)).encode("utf-8")

    md5_bytes = hashlib.md5(combined).digest()
    md5_base64 = base64.b64encode(md5_bytes).decode("utf-8")

    intermediate = md5_base64[:24]

    sha256_hash = hashlib.sha256(intermediate.encode("utf-8")).digest()

    return "0x" + sha256_hash.hex().upper()

def load_hash_store():
    users = {}

    with open(HASH_FILE, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        
        for row in reader:
            login = clean(row.get("login"))
            account_number = clean(row.get("ubos_accountnumber"))
            stored_hash = clean(row.get("stored_hash"))

            if login:
                users[login] = {
                    "account_number": account_number,
                    "stored_hash": stored_hash
                }

    return users

def okta_response(is_verified):
    credential_status = "VERIFIED" if is_verified else "UNVERIFIED"

    return jsonify({
        "commands": [
            {
                "type": "com.okta.action.update",
                "value": {
                    "credential": credential_status
                }
            }
        ]
    })

@app.route("/passwordImport", methods=["POST"])
def password_import():
    data = request.get_json()

    username = data["data"]["context"]["credential"]["username"]
    password = data["data"]["context"]["credential"]["password"]
    #print("looking for user:", repr(username), flush=True)
    users = load_hash_store()
    #print("Available user:", list(users.keys()), flush=True)
    user = users.get(username)

    if not user:
        return okta_response(False)

    generated_hash = custom_hash_hex(user["account_number"], password)
    stored_hash = user["stored_hash"]

    print("Username:", username)
    print("Generated:", generated_hash)
    print("Stored   :", stored_hash)

    if generated_hash == stored_hash:
        return okta_response(True)

    return okta_response(False)


if __name__ == "__main__":
    app.run(port=5000)
        