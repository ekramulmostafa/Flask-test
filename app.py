from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///home/mostafa/Desktop/Flask tests/flask_jwt_fullapp_test/todo.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'X-Access-Token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:

            data = jwt.decode(token, app.config['SECRET_KEY'])
            print(data)
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform this action!'}), 401

    users = User.query.all()
    ourput = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        ourput.append(user_data)

    return jsonify({'users': ourput})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform this action!'}), 401

    if not user:
        return jsonify({'message': 'No user found!'}), 404

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'users': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(create_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform this action!'}), 401

    data = request.get_json()
    hash_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'], password=hash_password, admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'user created'}), 200


@app.route('/user/<public_id>', methods=['PATCH'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform this action!'}), 401

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'}), 404

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'User have been promoted'}), 200


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def method_name(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform this action!'}), 401

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'user have been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'admin': user.admin, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')}), 200

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    data = []
    results = Todo.query.filter_by(user_id=current_user.id).all()

    for result in results:
        singleResult = {}
        singleResult['id'] = result.id
        singleResult['text'] = result.text
        singleResult['complete'] = result.complete

        data.append(singleResult)

    return jsonify({'todos': data})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return make_response('Do not found todo', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete
    return jsonify({'todo': todo_data}), 200


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'Todo created!'}), 200


@app.route('/todo/<todo_id>', methods=['PATCH'])
@token_required
def update_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return make_response('Do not found todo', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    data = request.get_json()
    todo.complete = data['complete']
    todo.text = data['text']

    db.session.commit()

    return jsonify({'': 'Updated Complete!'}), 200


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return make_response('Do not found todo', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message': 'Todo deleted!'}), 200


if __name__ == '__main__':
    app.run(debug=True)
