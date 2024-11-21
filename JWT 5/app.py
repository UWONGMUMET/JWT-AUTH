from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200
    
    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({'username': user.username})

if __name__ == '__main__':
    app.run(debug=True)


# validasi token
# fitur logout