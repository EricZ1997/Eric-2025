from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
import re
import json
import os

app = Flask(__name__)
auth = HTTPBasicAuth()

USER_FILE = "users.json"

def load_users():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)
    with open(USER_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def is_valid_user_id(uid):
    return isinstance(uid, str) and 6 <= len(uid) <= 20 and re.match(r"^[A-Za-z0-9]+$", uid)

def is_valid_password(pw):
    if not isinstance(pw, str) or not 8 <= len(pw) <= 20:
        return False
    if re.search(r"[\s\x00-\x1F]", pw):
        return False
    return True

def is_valid_nickname(nick):
    if nick == "":
        return True
    return isinstance(nick, str) and len(nick) <= 30 and not re.search(r"[\x00-\x1F]", nick)

def is_valid_comment(comment):
    if comment == "":
        return True
    return isinstance(comment, str) and len(comment) <= 100 and not re.search(r"[\x00-\x1F]", comment)

@auth.verify_password
def verify_password(user_id, password):
    users = load_users()
    user = users.get(user_id)
    if not user:
        return None
    if not check_password_hash(user["password"], password):
        return None
    return user_id

@auth.error_handler
def unauthorized():
    return jsonify({"message": "Authentication failed"}), 401

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get("user_id")
    password = data.get("password")
    if not user_id or not password:
        return jsonify({
            "message": "Account creation failed",
            "cause": "Required user_id and password"
        }), 400
    if not is_valid_user_id(user_id):
        if not (6 <= len(user_id) <= 20):
            cause = "Input length is incorrect"
        else:
            cause = "Incorrect character pattern"
        return jsonify({
            "message": "Account creation failed",
            "cause": cause
        }), 400
    if not is_valid_password(password):
        if not (8 <= len(password) <= 20):
            cause = "Input length is incorrect"
        else:
            cause = "Incorrect character pattern"
        return jsonify({
            "message": "Account creation failed",
            "cause": cause
        }), 400
    users = load_users()
    if user_id in users:
        return jsonify({
            "message": "Account creation failed",
            "cause": "Already same user_id is used"
        }), 400
    users[user_id] = {
        "password": generate_password_hash(password),
        "nickname": user_id,
        "comment": ""
    }
    save_users(users)
    return jsonify({
        "message": "Account successfully created",
        "user": {
            "user_id": user_id,
            "nickname": user_id
        }
    }), 200

@app.route('/users/<user_id>', methods=['GET'])
@auth.login_required
def get_user(user_id):
    users = load_users()
    # 如果找不到用户，404
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404
    # 如果认证通过，返回用户信息
    user = users[user_id]
    result = {
        "message": "User details by user_id",
        "user": {
            "user_id": user_id,
            "nickname": user.get("nickname", user_id),
            "comment": user.get("comment", "")
        }
    }
    return jsonify(result), 200
    else:
        return jsonify({
            "message": "User details by user_id",
            "user": {
                "user_id": user_id,
                "nickname": user.get("nickname", user_id)
            }
        }), 200

@app.route("/users/<user_id>", methods=["PATCH"])
@auth.login_required
def update_user(user_id):
    users = load_users()
    user = users.get(user_id)
    if not user:
        return jsonify({"message": "No user found"}), 404
    auth_user = auth.current_user()
    if auth_user != user_id:
        return jsonify({"message": "No permission for update"}), 403

    data = request.get_json(force=True, silent=True) or {}
    # user_id或password字段不可更新
    if "user_id" in data or "password" in data:
        return jsonify({
            "message": "User updation failed",
            "cause": "Not updatable user_id and password"
        }), 400
    nickname = data.get("nickname")
    comment = data.get("comment")
    # 必须有一个字段
    if nickname is None and comment is None:
        return jsonify({
            "message": "User updation failed",
            "cause": "Required nickname or comment"
        }), 400
    if nickname is not None and not is_valid_nickname(nickname):
        return jsonify({
            "message": "User updation failed",
            "cause": "Invalid nickname or comment"
        }), 400
    if comment is not None and not is_valid_comment(comment):
        return jsonify({
            "message": "User updation failed",
            "cause": "Invalid nickname or comment"
        }), 400
    # 空字符串处理
    if nickname is not None:
        if nickname == "":
            user["nickname"] = user_id
        else:
            user["nickname"] = nickname
    if comment is not None:
        if comment == "":
            user["comment"] = ""
        else:
            user["comment"] = comment
    users[user_id] = user
    save_users(users)
    return jsonify({
        "message": "User successfully updated",
        "user": [{
            "nickname": user.get("nickname", user_id),
            "comment": user.get("comment", "")
        }]
    }), 200

@app.route("/close", methods=["POST"])
@auth.login_required
def close_account():
    user_id = auth.current_user()
    users = load_users()
    if user_id not in users:
        return jsonify({"message": "Authentication failed"}), 401
    users.pop(user_id)
    save_users(users)
    return jsonify({"message": "Account and user successfully removed"}), 200

import os
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

