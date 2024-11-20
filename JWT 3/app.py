import os
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'defaultsecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'defaultjwtsecretkey')

db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

class UserProfile(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if user:
            return {'username': user.username}, 200
        return {'message': 'User not found'}, 404

class UserUpdate(Resource):
    @jwt_required()
    def put(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user_id = get_jwt_identity()
        
        user = User.query.get(user_id)
        if user:
            if username:
                user.username = username
            if password:
                user.password = password
            db.session.commit()
            return {'message': 'User details updated successfully'}, 200

        return {'message': 'User not found'}, 404

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            token = create_access_token(identity=user.id)
            return {'access_token': token}, 200

        return {'message': 'Invalid username or password'}, 401

api.add_resource(UserLogin, '/login')
api.add_resource(UserProfile, '/profile')
api.add_resource(UserUpdate, '/update')

if __name__ == '__main__':
    app.run(debug=True)
