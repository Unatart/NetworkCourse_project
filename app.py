from flask import render_template
from flask import request, abort, make_response, jsonify
from flask import Flask

import json
import uuid
import peewee
from peewee import *
from passlib.hash import pbkdf2_sha256
from valid.valid import Validator

app = Flask(__name__)

sqlite_db = SqliteDatabase('backenddb/backend.sqlite')


def init_tables():
    with sqlite_db:
        sqlite_db.create_tables([User, Token, Stats], safe=True)


class BaseModel(Model):
    class Meta:
        database = sqlite_db


class User(BaseModel):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField()


class Token(BaseModel):
    value = TextField(null=True)
    user = ForeignKeyField(model=User, on_delete='CASCADE')


class Stats(BaseModel):
    connections = TextField(default=0)
    user = ForeignKeyField(model=User, on_delete='CASCADE')


def generate_password_hash(password):
    return pbkdf2_sha256.encrypt(password, rounds=200000, salt_size=16)


def generate_token():
    return str(uuid.uuid4())


@app.route('/api/users/<string:username>', methods=['GET'])
def get_user_info_by_username(username):
    try:
        with sqlite_db.atomic():
            req_token = request.cookies['TOKEN']
            user = User.get(User.username == username)
            if req_token == Token.get(Token.user == user).value:
                return jsonify({'username': user.username, 'email': user.email})
            else:
                abort(403)
    except KeyError:
        abort(400)
    except User.DoesNotExist:
        abort(404)


@app.route('/api/users/<string:username>/stats', methods=['GET'])
def on_get(username):
    try:
        with sqlite_db.atomic():
            req_token = request.cookies['TOKEN']
            user = User.get(User.username == username)
            token = Token.get(Token.user == user)
            if req_token == token.value:
                stats = Stats.get(Stats.user == user)
                return jsonify({'username': user.username, 'connections': stats.connections})
            else:
                abort(403)

    except KeyError:
        abort(400)

    except User.DoesNotExist:
        abort(404)


@app.route('/api/users', methods=['POST'])
def create_user():
    try:
        with sqlite_db.atomic():
            req_user = json.loads(request.data)
            if req_user is None or not 'email' in req_user or not 'username' in req_user \
                    or not 'password' in req_user or not Validator.validate_password(req_user['password']) \
                    or not Validator.validate_email(req_user['email']) \
                    or not Validator.validate_username(req_user['username']):
                raise ValueError

            req_user['password'] = generate_password_hash(req_user['password'])

            new_user = User(**req_user)
            new_user.save()
            Stats(user=new_user).save()
            token = generate_token()
            Token(user=new_user, value=token).save()

            resp = make_response(jsonify({'username': new_user.username, 'email': new_user.email}), 201)
            resp.set_cookie('TOKEN', token)
            return resp
    except peewee.IntegrityError:
        abort(400)
    except ValueError:
        abort(400)
    except KeyError:
        abort(400)


@app.route('/api/login', methods=['POST'])
def get_token():
    req_user = json.loads(request.data)
    try:
        with sqlite_db.atomic():
            if 'email' in req_user:
                db_user = User.get(User.email == req_user['email'])
            else:
                db_user = User.get(User.username == req_user['username'])
            if not pbkdf2_sha256.verify(req_user['password'], db_user.password):
                abort(403)
            token = Token.get(Token.user == db_user)
            token.value = str(uuid.uuid4())
            token.save()

            resp = make_response(jsonify({'username': db_user.username, 'email': db_user.email}))
            resp.set_cookie('TOKEN', token.value)
            return resp

    except KeyError:
        abort(400)
    except User.DoesNotExist:
        abort(404)


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/signin.html")
def login():
    return render_template('signin.html')


@app.route("/register.html")
def register():
    return render_template('register.html')


if __name__ == '__main__':
    app.run(threaded=True, debug=True)
