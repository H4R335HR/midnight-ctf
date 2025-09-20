#!/usr/bin/env python3

import os
import hashlib
import re
import base64
import json
import csv
from io import StringIO
from flask import jsonify, make_response, request
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError, Length
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
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
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
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=20, message="Username must be between 3 and 20 characters")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message="Password must be at least 6 characters")
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')
    
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
                return new_secret_plaintext
        
        # Update hash for next iteration (chaining)
        current_hash = hashlib.sha512(new_secret_plaintext.encode('utf-8')).hexdigest()
    
    return None

# Improved flag mapping loader - add this right after the existing mapping loading code
def reload_flag_mappings():
    """Reload flag mappings with better error handling"""
    global flag_mappings
    flag_mappings = []
    
    try:
        with open(MAPPING_FILE, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):  # Skip empty lines and comments
                    continue
                    
                parts = line.split('|')
                if len(parts) >= 3:
                    filepath, old_secret, secret_type = parts[0], parts[1], parts[2]
                    
                    # Create mapping with all fields always present
                    mapping = {
                        'filepath': filepath.strip() if filepath.strip() else f'Challenge_{line_num}',
                        'old_secret': old_secret.strip() if old_secret.strip() else 'N/A',
                        'secret_type': secret_type.strip() if secret_type.strip() else 'unknown',
                        'challenge_name': os.path.basename(filepath).replace('_', ' ').title() if filepath.strip() else f'Challenge {line_num}'
                    }
                    flag_mappings.append(mapping)
                    print(f"Loaded mapping {line_num}: {mapping}")  # Debug output
                else:
                    print(f"Warning: Line {line_num} in {MAPPING_FILE} has insufficient parts: {parts}")
                    
    except FileNotFoundError:
        print(f"Warning: Mapping file {MAPPING_FILE} not found")
    except Exception as e:
        print(f"Error loading mappings: {e}")


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
        user = User(
            username=form.username.data,
            email=form.email.data
        )
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
            session['email'] = user.email  # Keep email for flag generation
            session['username'] = user.username  # Add username for display
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash(f'Welcome back, {user.username}!', 'success')
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
        # Use email from session for flag generation (keeps compatibility)
        expected_flag = generate_expected_flag_for_challenge(challenge_id, session['email'])
        
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
    # Group users by username and count their solved challenges
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
            'username': user.username,  # Changed from email to username
            'solved': solved_count,
            'last_solve': max([sc.solved_on for sc in user.solved_challenges]) if user.solved_challenges else None
        })
    
    # Add total challenges count for progress bar
    total_challenges = len(flag_mappings)
    
    return render_template('scoreboard.html', scoreboard=scoreboard_data, total_challenges=total_challenges)


@app.route('/admin')
@login_required
def admin():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('challenges'))
    
    users = User.query.all()
    solves = SolvedChallenge.query.order_by(SolvedChallenge.solved_on.desc()).all()
    
    # Calculate additional stats for the template
    total_users = len(users)
    active_users = len(set(solve.user_id for solve in solves))
    
    # Enhanced challenge data - directly use the flag_mappings data
    enhanced_challenges = []
    for i, challenge in enumerate(flag_mappings):
        challenge_solves = [s for s in solves if s.challenge_index == i]
        success_rate = (len(challenge_solves) / total_users * 100) if total_users > 0 else 0
        
        # Use the actual data from flag_mappings (which debug shows is correct)
        enhanced_challenge = {
            'index': i,
            'filepath': challenge['filepath'],  # Direct access, no .get()
            'secret_type': challenge['secret_type'],  # Direct access
            'old_secret': challenge['old_secret'],  # Direct access
            'challenge_name': challenge['challenge_name'],  # Direct access
            'description': get_challenge_description(i),
            'solves': len(challenge_solves),
            'success_rate': round(success_rate, 1)
        }
        
        enhanced_challenges.append(enhanced_challenge)
    
    # Debug print to verify data structure
    print("=== ADMIN ROUTE DEBUG ===")
    for i, challenge in enumerate(enhanced_challenges):
        print(f"Challenge {i}: filepath='{challenge['filepath']}', secret_type='{challenge['secret_type']}', old_secret='{challenge['old_secret'][:20]}...'")
    print("=== END DEBUG ===")
    
    return render_template(
        'admin.html', 
        users=users, 
        challenges=enhanced_challenges,  # This should now have all data
        solves=solves,
        total_users=total_users,
        active_users=active_users,
        flag_mappings=flag_mappings  # Keep original for compatibility
    )


# Add this route to manually refresh mappings if needed
@app.route('/admin/refresh_mappings', methods=['POST'])
@login_required
def refresh_mappings():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    reload_flag_mappings()
    return jsonify({
        'success': True, 
        'message': f'Reloaded {len(flag_mappings)} challenge mappings',
        'mappings_count': len(flag_mappings)
    })

@app.route('/admin/debug')
@login_required
def admin_debug():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    debug_info = {
        'mapping_file': MAPPING_FILE,
        'flag_mappings_count': len(flag_mappings),
        'flag_mappings_details': []
    }
    
    for i, mapping in enumerate(flag_mappings):
        debug_info['flag_mappings_details'].append({
            'index': i,
            'mapping_data': mapping,
            'mapping_keys': list(mapping.keys()) if isinstance(mapping, dict) else 'Not a dict',
            'filepath_value': mapping.get('filepath', 'MISSING') if isinstance(mapping, dict) else 'N/A',
            'old_secret_value': mapping.get('old_secret', 'MISSING') if isinstance(mapping, dict) else 'N/A',
            'secret_type_value': mapping.get('secret_type', 'MISSING') if isinstance(mapping, dict) else 'N/A'
        })
    
    return jsonify(debug_info)

@app.route('/admin/export')
@login_required
def admin_export():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    export_type = request.args.get('type', 'users')
    
    if export_type == 'users':
        # Export users data
        users = User.query.all()
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Username', 'Email', 'Registered On', 'Last Login', 'Is Admin', 'Challenges Solved'])
        
        for user in users:
            writer.writerow([
                user.id,
                user.username,
                user.email,
                user.registered_on.strftime('%Y-%m-%d %H:%M:%S') if user.registered_on else '',
                user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else '',
                user.is_admin,
                len(user.solved_challenges)
            ])
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=users_export.csv'
        return response
    
    elif export_type == 'solves':
        # Export solves data
        solves = SolvedChallenge.query.all()
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['User ID', 'Username', 'Challenge Index', 'Challenge Name', 'Solved On', 'Flag Submitted'])
        
        for solve in solves:
            challenge_name = get_challenge_description(solve.challenge_index)
            writer.writerow([
                solve.user_id,
                solve.user.username,
                solve.challenge_index,
                challenge_name,
                solve.solved_on.strftime('%Y-%m-%d %H:%M:%S') if solve.solved_on else '',
                solve.flag_submitted[:50] + '...' if len(solve.flag_submitted) > 50 else solve.flag_submitted
            ])
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=solves_export.csv'
        return response
    
    return jsonify({'error': 'Invalid export type'}), 400


@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Don't allow removing admin from yourself
    if target_user.id == current_user.id:
        return jsonify({'error': 'Cannot modify your own admin status'}), 400
    
    target_user.is_admin = not target_user.is_admin
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'is_admin': target_user.is_admin,
        'message': f'User {target_user.username} admin status updated'
    })


@app.route('/admin/user/<int:user_id>/delete', methods=['DELETE'])
@login_required
def delete_user(user_id):
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Don't allow deleting yourself or other admins
    if target_user.id == current_user.id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    if target_user.is_admin:
        return jsonify({'error': 'Cannot delete admin users'}), 400
    
    # Delete user's solves first
    SolvedChallenge.query.filter_by(user_id=user_id).delete()
    db.session.delete(target_user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {target_user.username} deleted'})


@app.route('/admin/reset_challenges', methods=['POST'])
@login_required
def reset_challenges():
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete all solved challenges
    SolvedChallenge.query.delete()
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'All challenge progress has been reset'})


@app.route('/admin/stats')
@login_required
def admin_stats():
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Calculate detailed statistics
    total_users = User.query.count()
    total_challenges = len(flag_mappings)
    total_solves = SolvedChallenge.query.count()
    
    # Active users (users who have solved at least one challenge)
    active_users = db.session.query(User.id).join(SolvedChallenge).distinct().count()
    
    # Challenge completion rates
    challenge_stats = []
    for i, challenge in enumerate(flag_mappings):
        solves = SolvedChallenge.query.filter_by(challenge_index=i).count()
        success_rate = (solves / total_users * 100) if total_users > 0 else 0
        
        challenge_stats.append({
            'index': i,
            'name': get_challenge_description(i),
            'filepath': challenge.get('filepath', 'N/A'),
            'secret_type': challenge.get('secret_type', 'unknown'),
            'solves': solves,
            'success_rate': round(success_rate, 1)
        })
    
    # Recent activity (last 10 solves)
    recent_solves = db.session.query(SolvedChallenge, User).join(User).order_by(SolvedChallenge.solved_on.desc()).limit(10).all()
    recent_activity = []
    for solve, user in recent_solves:
        recent_activity.append({
            'username': user.username,
            'challenge_index': solve.challenge_index,
            'challenge_name': get_challenge_description(solve.challenge_index),
            'solved_on': solve.solved_on.strftime('%Y-%m-%d %H:%M:%S') if solve.solved_on else 'N/A'
        })
    
    # Top performers
    top_users = db.session.query(
        User.username,
        db.func.count(SolvedChallenge.id).label('solve_count'),
        db.func.max(SolvedChallenge.solved_on).label('last_solve')
    ).join(SolvedChallenge).group_by(User.id).order_by(db.desc('solve_count')).limit(10).all()
    
    top_performers = []
    for username, solve_count, last_solve in top_users:
        top_performers.append({
            'username': username,
            'solve_count': solve_count,
            'completion_rate': round((solve_count / total_challenges) * 100, 1),
            'last_solve': last_solve.strftime('%Y-%m-%d') if last_solve else 'N/A'
        })
    
    return jsonify({
        'overview': {
            'total_users': total_users,
            'active_users': active_users,
            'total_challenges': total_challenges,
            'total_solves': total_solves,
            'avg_solves_per_user': round(total_solves / total_users, 2) if total_users > 0 else 0
        },
        'challenge_stats': challenge_stats,
        'recent_activity': recent_activity,
        'top_performers': top_performers
    })


@app.route('/admin/user/<int:user_id>/details')
@login_required
def user_details(user_id):
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get user's solved challenges with timestamps
    solved_challenges = db.session.query(SolvedChallenge).filter_by(user_id=user_id).order_by(SolvedChallenge.solved_on).all()
    
    solves_data = []
    for solve in solved_challenges:
        solves_data.append({
            'challenge_index': solve.challenge_index,
            'challenge_name': get_challenge_description(solve.challenge_index),
            'solved_on': solve.solved_on.strftime('%Y-%m-%d %H:%M:%S') if solve.solved_on else 'N/A',
            'flag_submitted': solve.flag_submitted[:50] + '...' if len(solve.flag_submitted) > 50 else solve.flag_submitted
        })
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'registered_on': user.registered_on.strftime('%Y-%m-%d %H:%M:%S') if user.registered_on else 'N/A',
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'N/A',
            'is_admin': user.is_admin,
            'total_solves': len(solved_challenges)
        },
        'solved_challenges': solves_data
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')