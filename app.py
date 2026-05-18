from flask import Flask, render_template, request, session
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from datetime import datetime

app = Flask(__name__)
app.secret_key = "change-this-secret-key-for-session-history"


# -----------------------------
# HELPERS
# -----------------------------

def add_history(operation, status):
    history = session.get("history", [])

    history.insert(0, {
        "operation": operation,
        "status": status,
        "time": datetime.now().strftime("%H:%M:%S")
    })

    session["history"] = history[:6]


def is_error(result):
    return result.startswith("Error:")


# -----------------------------
# FERNET / SYMMETRIC ENCRYPTION
# -----------------------------

def generate_fernet_key():
    return Fernet.generate_key().decode()


def fernet_encrypt(message, key):
    try:
        if not message or not key:
            return "Error: Please enter both text and Fernet key."

        f = Fernet(key.encode())
        encrypted_message = f.encrypt(message.encode())
        return encrypted_message.decode()

    except Exception:
        return "Error: Invalid Fernet key or message."


def fernet_decrypt(encrypted_message, key):
    try:
        if not encrypted_message or not key:
            return "Error: Please enter both encrypted text and Fernet key."

        f = Fernet(key.encode())
        decrypted_message = f.decrypt(encrypted_message.encode())
        return decrypted_message.decode()

    except Exception:
        return "Error: Invalid Fernet key or encrypted text."


# -----------------------------
# RSA / ASYMMETRIC ENCRYPTION
# -----------------------------

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem


def rsa_encrypt(message, public_key_text):
    try:
        if not message or not public_key_text:
            return "Error: Please enter text and public key."

        public_key = serialization.load_pem_public_key(public_key_text.encode())

        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted).decode()

    except Exception:
        return "Error: Invalid public key or message too long."


def rsa_decrypt(encrypted_message, private_key_text):
    try:
        if not encrypted_message or not private_key_text:
            return "Error: Please enter encrypted text and private key."

        private_key = serialization.load_pem_private_key(
            private_key_text.encode(),
            password=None
        )

        encrypted_bytes = base64.b64decode(encrypted_message.encode())

        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted.decode()

    except Exception:
        return "Error: Invalid private key or encrypted text."


# -----------------------------
# MAIN ROUTE
# -----------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    result_title = ""
    active_section = ""
    result_target = ""

    fernet_key = ""
    fernet_message = ""

    rsa_private_key = ""
    rsa_public_key = ""
    rsa_message = ""

    if request.method == "POST":
        action = request.form.get("action")

        fernet_key = request.form.get("fernet_key", "")
        fernet_message = request.form.get("message", "")

        rsa_public_key = request.form.get("rsa_public_key", "")
        rsa_private_key = request.form.get("rsa_private_key", "")
        rsa_message = request.form.get("rsa_message", "")

        if action == "clear_all":
            fernet_key = ""
            fernet_message = ""
            rsa_public_key = ""
            rsa_private_key = ""
            rsa_message = ""
            result = "All fields cleared successfully."
            result_title = "Fields Cleared"
            active_section = "overview"
            result_target = ""
            add_history("Clear All Fields", "Success")

        elif action == "clear_history":
            session["history"] = []
            result = "Operation history cleared successfully."
            result_title = "History Cleared"
            active_section = "history"
            result_target = ""

        elif action == "generate_fernet_key":
            fernet_key = generate_fernet_key()
            result = fernet_key
            result_title = "Fernet Key Generated"
            active_section = "fernet"
            result_target = "fernet_key"
            add_history("Generate Fernet Key", "Success")

        elif action == "fernet_encrypt":
            result = fernet_encrypt(fernet_message, fernet_key)
            result_title = "Fernet Encryption Result"
            active_section = "fernet"
            result_target = "fernet_message"
            add_history("Fernet Encryption", "Error" if is_error(result) else "Success")

        elif action == "fernet_decrypt":
            result = fernet_decrypt(fernet_message, fernet_key)
            result_title = "Fernet Decryption Result"
            active_section = "fernet"
            result_target = "fernet_message"
            add_history("Fernet Decryption", "Error" if is_error(result) else "Success")

        elif action == "generate_rsa_keys":
            rsa_private_key, rsa_public_key = generate_rsa_keys()
            result = "RSA public and private keys generated successfully."
            result_title = "RSA Keys Generated"
            active_section = "rsa"
            result_target = ""
            add_history("Generate RSA Keys", "Success")

        elif action == "rsa_encrypt":
            result = rsa_encrypt(rsa_message, rsa_public_key)
            result_title = "RSA Encryption Result"
            active_section = "rsa"
            result_target = "rsa_message"
            add_history("RSA Encryption", "Error" if is_error(result) else "Success")

        elif action == "rsa_decrypt":
            result = rsa_decrypt(rsa_message, rsa_private_key)
            result_title = "RSA Decryption Result"
            active_section = "rsa"
            result_target = "rsa_message"
            add_history("RSA Decryption", "Error" if is_error(result) else "Success")

    return render_template(
        "index.html",
        result=result,
        result_title=result_title,
        active_section=active_section,
        result_target=result_target,
        fernet_key=fernet_key,
        fernet_message=fernet_message,
        rsa_private_key=rsa_private_key,
        rsa_public_key=rsa_public_key,
        rsa_message=rsa_message,
        history=session.get("history", [])
    )


if __name__ == "__main__":
    app.run(debug=True)