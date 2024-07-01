from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'

# JWT configuration
app.config['JWT_SECRET_KEY'] = 'jwt_secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Example: token expires in 1 hour

db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Flask-Login callback to reload the user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all tables function
def create_tables():
    with app.app_context():
        db.create_all()

# Routes for authentication

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', None)
        password = request.form.get('password', None)
        if not email or not password:
            return jsonify({'message': 'Missing email or password in request'}), 400
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'User already exists'}), 400
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', None)
        password = request.form.get('password', None)
        if not email or not password:
            return jsonify({'message': 'Missing email or password in request'}), 400
        user = User.query.filter_by(email=email).first()
        if user and user.password == password:
            login_user(user)
            access_token = create_access_token(identity=user.id)
            session['access_token'] = access_token
            return redirect(url_for('protected'))
        return jsonify({'message': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('access_token', None)
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    access_token = session.get('access_token')
    return render_template('protected.html', current_user=current_user, access_token=access_token)

# Revoked tokens set (for token revocation)
revoked_tokens = set()

# Custom JWT revoked token check callback
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in revoked_tokens

if __name__ == '__main__':
    create_tables()  # Create database tables
    app.run(debug=True)
