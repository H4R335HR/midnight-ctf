#!/usr/bin/env python3

import os
import hashlib
import re
import base64
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
from datetime import datetime
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_me_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ctf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Load the flag mapping
MAPPING_FILE = os.environ.get('MAPPING_FILE', 'admin_mapping.txt')

# Parse the mapping file
flag_mappings = []
with open(MAPPING_FILE, 'r') as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) >= 3:
            filepath, old_secret, secret_type = parts[0], parts[1], parts[2]
            flag_mappings.append({
                'filepath': filepath,
                'old_secret': old_secret,
                'secret_type': secret_type,
                'challenge_name': os.path.basename(filepath).replace('_', ' ').title()
            })

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    solved_challenges = db.relationship('SolvedChallenge', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()


class SolvedChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_index = db.Column(db.Integer, nullable=False)
    solved_on = db.Column(db.DateTime, default=datetime.utcnow)
    flag_submitted = db.Column(db.String(256), nullable=False)


# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please login instead.')


class FlagSubmissionForm(FlaskForm):
    flag = StringField('Flag', validators=[DataRequired()])
    submit = SubmitField('Submit')


# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def generate_expected_flag_for_challenge(challenge_index, email):
    """Generate the expected flag for a specific challenge by simulating the chain."""
    current_hash = hashlib.sha512(email.encode('utf-8')).hexdigest()
    
    # Process challenges 0 through challenge_index to build the chain
    for i in range(challenge_index + 1):
        mapping = flag_mappings[i]
        suffix = current_hash[-4:]
        
        base_flag = mapping['old_secret']
        secret_type = mapping['secret_type']
        
        # Generate the new secret using the same logic as chainer.py
        if secret_type == 'plain text':
            new_secret_plaintext = base_flag + suffix
        elif secret_type == 'flag':
            m = re.match(r'flag\{(.+)\}', base_flag)
            if m:
                flag_content = m.group(1)
                new_secret_plaintext = f'{flag_content}_{suffix}'
            else:
                return None
        elif secret_type == 'base64':
            try:
                old_secret_plaintext = base64.b64decode(base_flag).decode('utf-8')
                new_secret_plaintext = old_secret_plaintext + suffix
            except:
                return None
        else:
            return None
        
        # If this is the challenge we want, format and return the flag
        if i == challenge_index:
            if secret_type == 'plain text':
                return new_secret_plaintext
            elif secret_type == 'flag':
                return f'flag{{{new_secret_plaintext}}}'
            elif secret_type == 'base64':
                return base64.b64encode(new_secret_plaintext.encode('utf-8')).decode('utf-8')
        
        # Update hash for next iteration (chaining)
        current_hash = hashlib.sha512(new_secret_plaintext.encode('utf-8')).hexdigest()
    
    return None


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('challenges'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('challenges'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['email'] = user.email
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('challenges'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


@app.route('/challenges')
@login_required
def challenges():
    user = User.query.get(session['user_id'])
    solved_indices = [sc.challenge_index for sc in user.solved_challenges]
    
    # Determine the highest challenge index this user has solved
    highest_solved = -1  # -1 means no challenges solved yet
    if solved_indices:
        highest_solved = max(solved_indices)
    
    # Only show challenges that are solved or the next available one
    available_challenges = []
    for i, mapping in enumerate(flag_mappings):
        # A challenge is available if:
        # - It's already been solved, OR
        # - It's the very first challenge (index 0) and no challenges solved yet, OR
        # - It's the next challenge after the highest solved one
        if i in solved_indices or (i == 0 and highest_solved == -1) or i == highest_solved + 1:
            challenge = {
                'id': i,
                'name': f"Challenge {i+1}",  # Generic name instead of showing file path
                'description': get_challenge_description(i),  # We'll define this function
                'solved': i in solved_indices
            }
            available_challenges.append(challenge)
    
    return render_template('challenges.html', challenges=available_challenges)

def get_challenge_description(challenge_index):
    # Map challenge indices to your cryptic questions
    descriptions = [
        "What's the wifi-pass?",                 # Challenge 0
        "Web flag?",                             # Challenge 1
        "What's password for Barista?",          # Challenge 2
        "User flag?",                            # Challenge 3
        "What's password for Manager?",          # Challenge 4
        "What's the manager flag?",              # Challenge 5
        "Root flag?"                             # Challenge 6
    ]
    
    # Return the description if available, otherwise a generic message
    if challenge_index < len(descriptions):
        return descriptions[challenge_index]
    else:
        return f"Challenge {challenge_index + 1}"


@app.route('/challenge/<int:challenge_id>', methods=['GET', 'POST'])
@login_required
def challenge(challenge_id):
    if challenge_id < 0 or challenge_id >= len(flag_mappings):
        flash('Challenge not found', 'danger')
        return redirect(url_for('challenges'))
    
    user = User.query.get(session['user_id'])
    solved_indices = [sc.challenge_index for sc in user.solved_challenges]
    
    # Determine if this challenge is available to the user
    highest_solved = -1
    if solved_indices:
        highest_solved = max(solved_indices)
    
    # Check if the user can access this challenge
    is_available = (challenge_id in solved_indices or 
                   (challenge_id == 0 and highest_solved == -1) or 
                   challenge_id == highest_solved + 1)
                   
    if not is_available:
        flash('You must solve the previous challenges first!', 'warning')
        return redirect(url_for('challenges'))
    
    challenge_info = flag_mappings[challenge_id]
    
    # Check if already solved
    solved = SolvedChallenge.query.filter_by(
        user_id=user.id, 
        challenge_index=challenge_id
    ).first()
    
    form = FlagSubmissionForm()
    if form.validate_on_submit():
        submitted_flag = form.flag.data.strip()
        expected_flag = generate_expected_flag_for_challenge(challenge_id, user.email)
        
        if submitted_flag == expected_flag:
            if not solved:
                new_solve = SolvedChallenge(
                    user_id=user.id,
                    challenge_index=challenge_id,
                    flag_submitted=submitted_flag
                )
                db.session.add(new_solve)
                db.session.commit()
            
            flash('Correct flag! Challenge solved!', 'success')
            return redirect(url_for('challenges'))
        else:
            flash('Incorrect flag. Try again!', 'danger')
    
    # Modified challenge description
    challenge_description = get_challenge_description(challenge_id)
    
    return render_template(
        'challenge.html',
        challenge={
            'challenge_name': f"Challenge {challenge_id + 1}",
            'description': challenge_description
        },
        form=form,
        solved=solved is not None
    )


@app.route('/scoreboard')
def scoreboard():
    # Group users by email and count their solved challenges
    users_with_solves = db.session.query(
        User, 
        db.func.count(SolvedChallenge.id).label('solved_count')
    ).join(
        SolvedChallenge, 
        User.id == SolvedChallenge.user_id, 
        isouter=True
    ).group_by(User.id).order_by(db.desc('solved_count')).all()
    
    scoreboard_data = []
    for i, (user, solved_count) in enumerate(users_with_solves, 1):
        scoreboard_data.append({
            'rank': i,
            'email': user.email,
            'solved': solved_count,
            'last_solve': max([sc.solved_on for sc in user.solved_challenges]) if user.solved_challenges else None
        })
    
    # Add total challenges count for progress bar
    total_challenges = len(flag_mappings)
    
    return render_template('scoreboard.html', scoreboard=scoreboard_data, total_challenges=total_challenges)


@app.route('/admin')
@login_required
def admin():
    # Only for demonstration - in production, add proper admin authentication
    if not session.get('email').endswith('@admin.ctf'):
        flash('Unauthorized access', 'danger')
        return redirect(url_for('challenges'))
    
    users = User.query.all()
    challenges = flag_mappings
    solves = SolvedChallenge.query.all()
    
    return render_template('admin.html', users=users, challenges=challenges, solves=solves)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')

