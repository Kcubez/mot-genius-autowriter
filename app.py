from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import logging
import json
import math
import google.generativeai as genai
import PIL.Image
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Myanmar timezone (UTC+6:30)
from datetime import timezone, timedelta
MYANMAR_TZ = timezone(timedelta(hours=6, minutes=30))

def get_myanmar_time():
    """Get current time in Myanmar timezone"""
    return datetime.now(MYANMAR_TZ)

def to_myanmar_time(utc_datetime):
    """Convert UTC datetime to Myanmar timezone"""
    if utc_datetime is None:
        return None
    if utc_datetime.tzinfo is None:
        utc_datetime = utc_datetime.replace(tzinfo=timezone.utc)
    return utc_datetime.astimezone(MYANMAR_TZ)


def format_datetime_iso(dt):
    """Return an ISO8601 string in UTC (Z suffix) for frontend consumption."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


import re

def add_facebook_trademark(content):
    """Add trademark symbol (™️) to Facebook mentions in content.
    
    This function adds the trademark emoji after 'Facebook' if it doesn't 
    already have one. Handles case-insensitive matching while preserving
    the original case of 'Facebook'.
    """
    if not content:
        return content
    
    # Pattern to match 'Facebook' that is NOT already followed by ™️ or ™
    # Using negative lookahead to avoid double-adding
    pattern = r'(Facebook)(?!\s*[™️]|™️|™)'
    
    # Replace with the matched text + trademark symbol
    result = re.sub(pattern, r'\1™️', content, flags=re.IGNORECASE)
    
    return result

app = Flask(__name__)
project_folder = os.path.dirname(os.path.abspath(__file__))

# Configure for PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL")

# If no DATABASE_URL, construct from individual components
if not DATABASE_URL:
    USER = os.getenv("user")
    PASSWORD = os.getenv("password")
    HOST = os.getenv("host")
    PORT = os.getenv("port")
    DBNAME = os.getenv("dbname")
    
    if all([USER, PASSWORD, HOST, PORT, DBNAME]):
        DATABASE_URL = f"postgresql+psycopg2://{USER}:{PASSWORD}@{HOST}:{PORT}/{DBNAME}?sslmode=require&connect_timeout=10&application_name=gemini-facebook-scheduler"
        logging.info("Using Supabase PostgreSQL database")
    else:
        raise ValueError("Database configuration missing. Please set DATABASE_URL or individual database environment variables.")
else:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Configure upload folder for different environments
if os.getenv('VERCEL'):
    # In Vercel serverless environment, use /tmp directory
    UPLOAD_FOLDER = '/tmp/uploads'
else:
    # In local development, use uploads folder in project directory
    UPLOAD_FOLDER = os.path.join(project_folder, 'uploads')

# Create upload folder (only works in writable environments)
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except OSError:
    # If we can't create the folder, log it but don't crash (serverless environment)
    logging.warning(f"Could not create upload folder: {UPLOAD_FOLDER}")
    pass

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "a-very-secret-key-for-development")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['FAVICON_VERSION'] = '3.0'  # Increment this to force favicon refresh
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB limit

# Session configuration for remember me functionality
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_DURATION'] = 2592000  # 30 days
app.config['PERMANENT_SESSION_LIFETIME'] = 2592000  # 30 days

# Database connection pool settings for better reliability
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 120,  # Recycle connections every 2 minutes
    'pool_pre_ping': True,  # Validate connections before use
    'pool_timeout': 20,
    'max_overflow': 0
}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    api_key = db.Column(db.Text, nullable=True)  # Store user's Gemini API key
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    locked_until = db.Column(db.DateTime, nullable=True)
    content_count = db.Column(db.Integer, default=0, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    subscription_start = db.Column(db.DateTime, nullable=True)  # Subscription start date
    user_type = db.Column(db.String(20), default='normal', nullable=True)
    subscription_duration = db.Column(db.String(20), nullable=True)
    contents = db.relationship('Content', backref='author', lazy=True, cascade='all, delete-orphan')
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.locked_until:
            # Convert locked_until to Myanmar time for comparison
            current_time = get_myanmar_time()
            if self.locked_until.tzinfo is None:
                # If locked_until is naive (UTC), make it timezone aware
                locked_until_utc = self.locked_until.replace(tzinfo=timezone.utc)
                locked_until_myanmar = locked_until_utc.astimezone(MYANMAR_TZ)
            else:
                locked_until_myanmar = self.locked_until.astimezone(MYANMAR_TZ)
            
            return locked_until_myanmar > current_time
        return False
    
    def record_failed_login(self):
        """Record a failed login attempt"""
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.now(timezone.utc)
        
        # Lock account after 3 failed attempts
        if self.failed_login_attempts >= 3:
            self.is_active = False
            # Set lock time in UTC but calculate 30 minutes from Myanmar time
            myanmar_now = get_myanmar_time()
            myanmar_lock_until = myanmar_now + timedelta(minutes=30)
            self.locked_until = myanmar_lock_until.astimezone(timezone.utc).replace(tzinfo=None)
        
        db.session.commit()
    
    def reset_failed_attempts(self):
        """Reset failed login attempts after successful login"""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.locked_until = None
        db.session.commit()
    
    def get_locked_until_myanmar(self):
        """Get locked_until time in Myanmar timezone for display"""
        if self.locked_until:
            if self.locked_until.tzinfo is None:
                # Assume UTC if no timezone info
                locked_until_utc = self.locked_until.replace(tzinfo=timezone.utc)
                return locked_until_utc.astimezone(MYANMAR_TZ)
            else:
                return self.locked_until.astimezone(MYANMAR_TZ)
        return None
    
    def is_account_expired(self):
        """Check if account has expired"""
        if not self.expires_at or self.is_admin:
            return False
        current_time = datetime.now(timezone.utc)
        if self.expires_at.tzinfo is None:
            expires_at_utc = self.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at_utc = self.expires_at.astimezone(timezone.utc)
        return expires_at_utc <= current_time
    
    def can_generate_content(self):
        """Check if user can generate more content - all users have unlimited"""
        return True
    
    def get_remaining_content_count(self):
        """Get remaining content generation count - unlimited for all"""
        if self.is_admin:
            return float('inf')
        return float('inf')
    
    def get_remaining_content_count_json(self):
        """Get remaining content generation count in JSON-safe format"""
        return "unlimited"
    
    def get_expires_at_myanmar(self):
        """Get expires_at time in Myanmar timezone for display"""
        if self.expires_at:
            if self.expires_at.tzinfo is None:
                expires_at_utc = self.expires_at.replace(tzinfo=timezone.utc)
                return expires_at_utc.astimezone(MYANMAR_TZ)
            else:
                return self.expires_at.astimezone(MYANMAR_TZ)
        return None
    
    def get_subscription_start_myanmar(self):
        """Get subscription_start time in Myanmar timezone for display"""
        if self.subscription_start:
            if self.subscription_start.tzinfo is None:
                subscription_start_utc = self.subscription_start.replace(tzinfo=timezone.utc)
                return subscription_start_utc.astimezone(MYANMAR_TZ)
            else:
                return self.subscription_start.astimezone(MYANMAR_TZ)
        return None
    
    def set_expiration_from_duration(self):
        """Set expires_at based on subscription_duration"""
        if not self.subscription_duration or self.is_admin:
            return
        
        current_time = datetime.now(timezone.utc)
        
        duration_map = {
            '1day': timedelta(days=1),
            '7days': timedelta(days=7),
            '1month': timedelta(days=30),
            '3months': timedelta(days=90),
            '6months': timedelta(days=180),
            '1year': timedelta(days=365)
        }
        
        if self.subscription_duration in duration_map:
            self.expires_at = current_time + duration_map[self.subscription_duration]
    
    def get_user_type_display(self):
        """Get user type for display"""
        if self.is_admin:
            return 'Admin'
        return 'Normal User'
    
    def get_subscription_display(self):
        """Get subscription duration for display"""
        if not self.subscription_duration:
            return 'N/A'
        
        display_map = {
            '1day': '1 Day',
            '7days': '7 Days',
            '1month': '1 Month',
            '3months': '3 Months',
            '6months': '6 Months',
            '1year': '1 Year'
        }
        
        return display_map.get(self.subscription_duration, self.subscription_duration)

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    purpose = db.Column(db.Text, nullable=True)
    writing_style = db.Column(db.String(100), nullable=True)
    audience = db.Column(db.Text, nullable=True)
    keywords = db.Column(db.Text, nullable=True)
    hashtags = db.Column(db.Text, nullable=True)
    cta = db.Column(db.Text, nullable=True)
    negative_constraints = db.Column(db.Text, nullable=True)
    reference_links = db.Column(db.Text, nullable=True)  # Store as JSON string
    image_path = db.Column(db.String(500), nullable=True)
    published = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logging.error(f"Error loading user {user_id}: {e}")
        # Try to rollback and retry once
        try:
            db.session.rollback()
            return db.session.get(User, int(user_id))
        except Exception as retry_error:
            logging.error(f"Retry failed for user {user_id}: {retry_error}")
            return None

# Custom validator for Gmail addresses
def validate_gmail(form, field):
    if not field.data.lower().endswith('@gmail.com'):
        raise ValidationError('Please use a Gmail address (@gmail.com)')

# Custom validator for password (no spaces)
def validate_password_no_spaces(form, field):
    if ' ' in field.data:
        raise ValidationError('Password cannot contain spaces')

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), validate_gmail])
    password = PasswordField('Password', validators=[DataRequired(), validate_password_no_spaces], render_kw={"placeholder": "Enter your password"})
    api_key = StringField('Gemini API Key', render_kw={"placeholder": "Enter your Gemini API Key"})
    remember_me = BooleanField('Remember me', default=False)
    submit = SubmitField('Login')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), validate_gmail])
    password = PasswordField('Password', validators=[DataRequired(), validate_password_no_spaces], render_kw={"placeholder": "Enter your password"})
    submit = SubmitField('Admin Login')

class UserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), validate_gmail])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6), validate_password_no_spaces], render_kw={"placeholder": "Enter password (minimum 6 characters)"})
    user_type = SelectField('User Type', choices=[('trial', 'Trial User'), ('normal', 'Normal User')], default='trial')
    is_admin = SelectField('Role', choices=[('False', 'User'), ('True', 'Admin')], default='False')
    expiration_date = StringField('Expiration Date', render_kw={"type": "date", "placeholder": "Select expiration date"})
    submit = SubmitField('Create User')


# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database error handling decorator
def handle_db_errors(f):
    """Decorator to handle database connection errors"""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Database error in {f.__name__}: {e}")
            
            # Check if it's a connection error
            if 'server closed the connection unexpectedly' in str(e) or 'connection' in str(e).lower():
                try:
                    # Try to rollback and close the session
                    db.session.rollback()
                    db.session.close()
                    
                    # Retry the function once
                    logging.info(f"Retrying {f.__name__} after connection error")
                    return f(*args, **kwargs)
                except Exception as retry_error:
                    logging.error(f"Retry failed for {f.__name__}: {retry_error}")
                    flash('Database connection error. Please try again.', 'error')
                    return redirect(url_for('login'))
            else:
                # For other database errors, rollback and re-raise
                db.session.rollback()
                raise e
    
    return decorated_function

@app.context_processor
def inject_now():
    return {
        'now': datetime.now(timezone.utc),
        'myanmar_now': get_myanmar_time()
    }

# Configure Google Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.5-flash')
    logging.info("Gemini API configured successfully")
else:
    logging.warning("GEMINI_API_KEY not found in environment variables")
    model = None

# Global error handlers
@app.errorhandler(Exception)
def handle_exception(e):
    """Handle uncaught exceptions"""
    # Check if it's a database connection error
    if 'server closed the connection unexpectedly' in str(e) or 'OperationalError' in str(type(e).__name__):
        logging.error(f"Database connection error: {e}")
        try:
            db.session.rollback()
            db.session.close()
        except:
            pass
        flash('Database connection lost. Please try logging in again.', 'error')
        return redirect(url_for('login'))
    
    # For other exceptions, log and show generic error
    logging.error(f"Unhandled exception: {e}")
    flash('An unexpected error occurred. Please try again.', 'error')
    return redirect(url_for('index'))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        # Pass along any URL parameters for toast notifications
        login_success = request.args.get('login_success')
        username = request.args.get('username')
        
        if current_user.is_admin:
            if login_success and username:
                return redirect(url_for('admin_dashboard', login_success=login_success, username=username))
            else:
                return redirect(url_for('admin_dashboard'))
        else:
            if login_success and username:
                return redirect(url_for('user_dashboard', login_success=login_success, username=username))
            else:
                return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@handle_db_errors
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        
        if user:
            
            # Check if account is deactivated by admin
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return redirect(url_for('login', login_error='true', message='Your account has been deactivated. Please contact an administrator'))
            
            # Check if subscription has started
            if user.subscription_start and not user.is_admin:
                current_time = datetime.now(timezone.utc)
                subscription_start_utc = user.subscription_start.replace(tzinfo=timezone.utc) if user.subscription_start.tzinfo is None else user.subscription_start
                
                if current_time < subscription_start_utc:
                    # Format the activation date for display
                    subscription_start_myanmar = subscription_start_utc.astimezone(MYANMAR_TZ)
                    activation_date_str = subscription_start_myanmar.strftime('%d %B %Y')
                    
                    error_message = f'Your account will be activated on {activation_date_str}. Please wait until then.'
                    flash(error_message, 'error')
                    return redirect(url_for('login', login_error='true', message=error_message))
            
            # Check password
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                # Redirect admins to admin login
                if user.is_admin:
                    flash('Please use admin login for administrative access.', 'info')
                    return redirect(url_for('admin_login'))
                
                # Successful login - store API key
                # API key is required for regular users
                if not form.api_key.data:
                    flash('API key is required for regular users', 'error')
                    return redirect(url_for('login', login_error='true', message='API key is required for regular users'))
                
                # Store API key
                user.api_key = form.api_key.data
                db.session.commit()
                
                login_user(user, remember=form.remember_me.data)
                flash(f'Welcome back, {user.email}!', 'success')
                # Add URL parameter for toast notification
                return redirect(url_for('index', login_success='true', username=user.email))
            else:
                # Failed password - just show error message
                flash('Invalid email or password', 'error')
                return redirect(url_for('login', login_error='true', message='Invalid email or password'))
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login', login_error='true', message='Invalid email or password'))
    
    return render_template('login.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
@handle_db_errors
def admin_login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    form = AdminLoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        
        if user:
            # Check if account is locked
            if user.is_account_locked():
                flash('Account is temporarily locked due to multiple failed login attempts. Please try again later.', 'error')
                return redirect(url_for('admin_login', login_error='true', message='Account is temporarily locked due to multiple failed login attempts'))
            
            # Check if account is deactivated
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return redirect(url_for('admin_login', login_error='true', message='Your account has been deactivated. Please contact an administrator'))
            
            # Only allow admin users
            if not user.is_admin:
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('admin_login', login_error='true', message='Access denied. Admin privileges required'))
            
            # Check password
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                # Successful login - reset failed attempts
                user.reset_failed_attempts()
                db.session.commit()
                
                login_user(user, remember=True)
                flash(f'Welcome back, Admin {user.email}!', 'success')
                return redirect(url_for('admin_dashboard', login_success='true', username=user.email))
            else:
                # Failed password - record attempt
                user.record_failed_login()
                remaining_attempts = 3 - user.failed_login_attempts
                
                if user.failed_login_attempts >= 3:
                    flash('Account deactivated due to 3 failed login attempts. Please contact an administrator.', 'error')
                    return redirect(url_for('admin_login', login_error='true', message='Account deactivated due to 3 failed login attempts'))
                else:
                    flash(f'Invalid password. {remaining_attempts} attempts remaining before account deactivation.', 'error')
                    return redirect(url_for('admin_login', login_error='true', message=f'Invalid password. {remaining_attempts} attempts remaining'))
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('admin_login', login_error='true', message='Invalid email or password'))
    
    return render_template('admin_login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    user_email = current_user.email
    is_admin = current_user.is_admin
    logout_user()
    flash(f'Goodbye {user_email}! You have been logged out successfully.', 'success')
    # Add URL parameter for toast notification
    if is_admin:
        return redirect(url_for('admin_login', logout_success='true', username=user_email))
    return redirect(url_for('login', logout_success='true', username=user_email))

@app.route('/admin')
@login_required
@handle_db_errors
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Get search and filter parameters
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    filter_status = request.args.get('filter', '', type=str)
    
    # Build query with search and filter
    query = User.query
    
    if search:
        query = query.filter(User.email.contains(search))
    
    if filter_status == 'active':
        query = query.filter(User.is_active == True)
    elif filter_status == 'inactive':
        query = query.filter(User.is_active == False)
    
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    total_users = User.query.count()
    total_contents = Content.query.count()
    recent_contents = Content.query.order_by(Content.created_at.desc()).limit(3).all()
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         total_users=total_users,
                         total_contents=total_contents,
                         recent_contents=recent_contents,
                         search=search,
                         filter_status=filter_status)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    form = UserForm()
    if form.validate_on_submit():
        # Check if email already exists (case-insensitive)
        existing_email = User.query.filter_by(email=form.email.data.lower()).first()
        
        if existing_email:
            flash('Email already exists', 'error')
            return redirect(url_for('create_user', user_error='true', message='Email already exists'))
        else:
            password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            is_admin = (form.is_admin.data == 'True')
            user_type = 'normal'  # Always create normal users
            
            # Set expiration date based on user type
            expires_at = None
            subscription_duration = None
            
            # Parse subscription_start FIRST (needed for expiration date validation)
            subscription_start = None
            subscription_start_str = request.form.get('subscription_start')
            if subscription_start_str:
                try:
                    # Get timezone offset from form (in minutes)
                    timezone_offset_minutes = request.form.get('timezone_offset', type=int)
                    
                    # Try datetime-local format first (YYYY-MM-DDTHH:MM)
                    try:
                        start_datetime_local = datetime.strptime(subscription_start_str, '%Y-%m-%dT%H:%M')
                    except ValueError:
                        # Fallback to date only format
                        start_date = datetime.strptime(subscription_start_str, '%Y-%m-%d')
                        start_datetime_local = datetime.combine(start_date.date(), datetime.min.time())
                    
                    # Convert from user's local timezone to UTC
                    if timezone_offset_minutes is not None:
                        user_tz = timezone(timedelta(minutes=-timezone_offset_minutes))
                        start_datetime_aware = start_datetime_local.replace(tzinfo=user_tz)
                    else:
                        # Fallback to Myanmar timezone
                        start_datetime_aware = start_datetime_local.replace(tzinfo=MYANMAR_TZ)
                    
                    start_datetime_utc = start_datetime_aware.astimezone(timezone.utc)
                    subscription_start = start_datetime_utc.replace(tzinfo=None)
                except ValueError as e:
                    logging.error(f"Subscription start date parsing error: {e}")
                    return jsonify({'error': f'Invalid subscription start date format: {e}'}), 400
            
            if not is_admin:
                # Normal users: use selected expiration date
                expiration_date_str = form.expiration_date.data
                
                if not expiration_date_str:
                    return jsonify({'error': 'Expiration date is required'}), 400
                
                try:
                    # Get timezone offset from form (in minutes)
                    timezone_offset_minutes = request.form.get('timezone_offset', type=int)
                    
                    # Try datetime-local format first (YYYY-MM-DDTHH:MM)
                    try:
                        expiry_datetime_local = datetime.strptime(expiration_date_str, '%Y-%m-%dT%H:%M')
                    except ValueError:
                        # Fallback to date only format
                        expiry_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
                        expiry_datetime_local = datetime.combine(expiry_date.date(), datetime.max.time())
                    
                    # Convert from user's local timezone to UTC
                    if timezone_offset_minutes is not None:
                        user_tz = timezone(timedelta(minutes=-timezone_offset_minutes))
                        expiry_datetime_aware = expiry_datetime_local.replace(tzinfo=user_tz)
                    else:
                        # Fallback to Myanmar timezone
                        expiry_datetime_aware = expiry_datetime_local.replace(tzinfo=MYANMAR_TZ)
                    
                    expiry_datetime_utc = expiry_datetime_aware.astimezone(timezone.utc)
                    
                    # Validate expiration date
                    now_utc = datetime.now(timezone.utc)
                    
                    # If subscription_start is set, validate against subscription_start
                    # Otherwise, validate against current time
                    if subscription_start:
                        subscription_start_utc = subscription_start.replace(tzinfo=timezone.utc)
                        if expiry_datetime_utc <= subscription_start_utc:
                            return jsonify({'error': 'Expiration date must be after the subscription start date'}), 400
                    else:
                        if expiry_datetime_utc <= now_utc:
                            return jsonify({'error': 'Expiration date/time cannot be in the past'}), 400
                    
                    expires_at = expiry_datetime_utc.replace(tzinfo=None)
                    
                    # Calculate duration for display
                    myanmar_now = get_myanmar_time()
                    days_diff = (expiry_datetime_local.date() - myanmar_now.date()).days
                    if days_diff <= 7:
                        subscription_duration = f'{days_diff}days'
                    elif days_diff <= 31:
                        subscription_duration = '1month'
                    elif days_diff <= 93:
                        subscription_duration = '3months'
                    elif days_diff <= 186:
                        subscription_duration = '6months'
                    else:
                        subscription_duration = '1year'
                    
                    logging.info(f"Normal user expiration set to: {expires_at} (Local: {expiry_datetime_local})")
                    
                except ValueError as e:
                    logging.error(f"Date parsing error: {e}")
                    return jsonify({'error': f'Invalid date format: {e}'}), 400
                except Exception as e:
                    logging.error(f"Error setting expiration date: {e}")
                    return jsonify({'error': f'Error setting expiration date: {str(e)}'}), 400
            
            try:
                user = User(
                    email=form.email.data.lower(),
                    password_hash=password_hash,
                    is_admin=is_admin,
                    user_type=user_type,
                    subscription_duration=subscription_duration,
                    subscription_start=subscription_start,
                    expires_at=expires_at
                )
                
                logging.info(f"Creating user: {form.email.data}, type: {user_type}, expires_at: {expires_at}")
                
                db.session.add(user)
                db.session.commit()
                
                logging.info(f"User {form.email.data} created successfully in database")
                flash(f'User {form.email.data} created successfully', 'success')
                # Add URL parameter for toast notification
                return redirect(url_for('admin_dashboard', user_created='true', username=form.email.data))
                
            except Exception as e:
                db.session.rollback()
                logging.error(f"Database error creating user: {e}")
                flash(f'Error creating user: {str(e)}', 'error')
                return redirect(url_for('create_user'))
    
    return render_template('create_user.html', form=form)

@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot modify your own status'}), 400
    
    try:
        old_status = user.is_active
        user.is_active = not user.is_active
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        print(f"User {user.email} (ID: {user_id}) {status} by admin {current_user.email}")
        
        return jsonify({
            'success': True, 
            'message': f'User {user.email} {status} successfully',
            'new_status': user.is_active
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error toggling user status: {e}")
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/admin/users/<int:user_id>/reset-attempts', methods=['POST'])
@login_required
def reset_user_attempts(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        old_attempts = user.failed_login_attempts
        user.reset_failed_attempts()
        
        # If user was deactivated due to failed attempts, reactivate them
        if not user.is_active and user.locked_until:
            user.is_active = True
            db.session.commit()
        
        print(f"Admin {current_user.email} reset failed attempts for user {user.email} (was: {old_attempts})")
        
        return jsonify({
            'success': True, 
            'message': f'Failed login attempts reset for {user.email}',
            'was_reactivated': not user.is_active and user.locked_until is not None
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting user attempts: {e}")
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Prevent editing self (security measure)
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot edit your own account'}), 400
    
    # GET request - return user data
    if request.method == 'GET':
        # Get timezone offset from query parameter (sent by JavaScript)
        timezone_offset_minutes = request.args.get('timezone_offset', type=int)
        
        # Format subscription_start for datetime-local input (YYYY-MM-DDTHH:MM)
        subscription_start_formatted = None
        if user.subscription_start:
            utc_start = user.subscription_start.replace(tzinfo=timezone.utc)
            
            if timezone_offset_minutes is not None:
                user_tz = timezone(timedelta(minutes=-timezone_offset_minutes))
                local_start = utc_start.astimezone(user_tz)
            else:
                local_start = utc_start.astimezone(MYANMAR_TZ)
            
            subscription_start_formatted = local_start.strftime('%Y-%m-%dT%H:%M')
        
        # Format expires_at for datetime-local input
        expires_at_formatted = None
        if user.expires_at:
            utc_expiry = user.expires_at.replace(tzinfo=timezone.utc)
            
            if timezone_offset_minutes is not None:
                user_tz = timezone(timedelta(minutes=-timezone_offset_minutes))
                local_expiry = utc_expiry.astimezone(user_tz)
            else:
                local_expiry = utc_expiry.astimezone(MYANMAR_TZ)
            
            expires_at_formatted = local_expiry.strftime('%Y-%m-%dT%H:%M')
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'user_type': user.user_type or 'normal',
                'subscription_duration': user.subscription_duration if hasattr(user, 'subscription_duration') else None,
                'subscription_start': subscription_start_formatted,
                'expires_at': expires_at_formatted,
                'is_active': user.is_active
            }
        })
    
    # POST request - update user data
    try:
        data = request.get_json()
        
        # Validate and update email
        new_email = data.get('email', '').lower().strip()
        if new_email and new_email != user.email:
            # Check if email already exists
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user:
                return jsonify({'error': 'Email already exists'}), 400
            user.email = new_email
        
        # Update password if provided
        new_password = data.get('password', '').strip()
        if new_password:
            if len(new_password) < 6:
                return jsonify({'error': 'Password must be at least 6 characters'}), 400
            if ' ' in new_password:
                return jsonify({'error': 'Password cannot contain spaces'}), 400
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # Update user type - always set to 'normal' since we removed trial option
        user.user_type = 'normal'
        
        # Parse subscription_start FIRST (needed for expiration date validation)
        subscription_start_for_validation = None
        subscription_start_str = data.get('subscription_start')
        if subscription_start_str:
            try:
                # Get timezone offset (in minutes)
                timezone_offset_str = data.get('timezone_offset')
                timezone_offset_minutes = int(timezone_offset_str) if timezone_offset_str is not None else None
                
                # Try datetime-local format first (YYYY-MM-DDTHH:MM)
                try:
                    start_datetime_local = datetime.strptime(subscription_start_str, '%Y-%m-%dT%H:%M')
                except ValueError:
                    # Fallback to date only format
                    start_date = datetime.strptime(subscription_start_str, '%Y-%m-%d')
                    start_datetime_local = datetime.combine(start_date.date(), datetime.min.time())
                
                # Convert from user's local timezone to UTC
                if timezone_offset_minutes is not None:
                    user_tz = timezone(timedelta(minutes=-timezone_offset_minutes))
                    start_datetime_aware = start_datetime_local.replace(tzinfo=user_tz)
                else:
                    # Fallback to Myanmar timezone
                    start_datetime_aware = start_datetime_local.replace(tzinfo=MYANMAR_TZ)
                
                start_datetime_utc = start_datetime_aware.astimezone(timezone.utc)
                subscription_start_for_validation = start_datetime_utc.replace(tzinfo=None)
                user.subscription_start = subscription_start_for_validation
            except ValueError as e:
                return jsonify({'error': f'Invalid subscription start date format: {str(e)}'}), 400
        
        # Get expiration date from request
        expiration_date_str = data.get('expiration_date')
        
        if not expiration_date_str:
            return jsonify({'error': 'Expiration date is required'}), 400
        
        try:
            # Get timezone offset (in minutes)
            timezone_offset_str = data.get('timezone_offset')
            timezone_offset_minutes = int(timezone_offset_str) if timezone_offset_str is not None else None
            
            # Try datetime-local format first (YYYY-MM-DDTHH:MM)
            try:
                expiry_datetime_local = datetime.strptime(expiration_date_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                # Fallback to date only format
                expiry_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
                expiry_datetime_local = datetime.combine(expiry_date.date(), datetime.max.time())
            
            # Convert from user's local timezone to UTC
            if timezone_offset_minutes is not None:
                user_tz = timezone(timedelta(minutes=-timezone_offset_minutes))
                expiry_datetime_aware = expiry_datetime_local.replace(tzinfo=user_tz)
            else:
                # Fallback to Myanmar timezone
                expiry_datetime_aware = expiry_datetime_local.replace(tzinfo=MYANMAR_TZ)
            
            expiry_datetime_utc = expiry_datetime_aware.astimezone(timezone.utc)
            
            # Validate expiration date
            now_utc = datetime.now(timezone.utc)
            
            # If subscription_start is set, validate against subscription_start
            # Otherwise, validate against current time
            if subscription_start_for_validation:
                subscription_start_utc = subscription_start_for_validation.replace(tzinfo=timezone.utc)
                if expiry_datetime_utc <= subscription_start_utc:
                    return jsonify({'error': 'Expiration date must be after the subscription start date'}), 400
            else:
                if expiry_datetime_utc <= now_utc:
                    return jsonify({'error': 'Expiration date/time cannot be in the past'}), 400
            
            user.expires_at = expiry_datetime_utc.replace(tzinfo=None)
            
            # Calculate duration for display
            myanmar_now = get_myanmar_time()
            days_diff = (expiry_datetime_local.date() - myanmar_now.date()).days
            if days_diff <= 7:
                user.subscription_duration = f'{days_diff}days'
            elif days_diff <= 31:
                user.subscription_duration = '1month'
            elif days_diff <= 93:
                user.subscription_duration = '3months'
            elif days_diff <= 186:
                user.subscription_duration = '6months'
            else:
                user.subscription_duration = '1year'
                    
        except ValueError as e:
            return jsonify({'error': f'Invalid date format: {str(e)}'}), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'user_type': user.user_type,
                'subscription_duration': user.subscription_duration if hasattr(user, 'subscription_duration') else None,
                'expires_at': user.expires_at.strftime('%Y-%m-%d') if user.expires_at else None
            }
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users/<int:user_id>/delete', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    user = db.session.get(User, user_id)
    if user and user.id != current_user.id:  # Can't delete self
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    
    return jsonify({'error': 'User not found or cannot delete self'}), 400

@app.route('/dashboard')
@login_required
@handle_db_errors
def contents_dashboard():
    """New contents dashboard with published/draft filtering"""
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    contents_query = Content.query.filter_by(user_id=current_user.id).order_by(Content.created_at.desc())
    total_count = contents_query.count()
    total_pages = max(1, math.ceil(total_count / per_page))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page
    contents = contents_query.offset(offset).limit(per_page).all()
    published_count = contents_query.filter_by(published=True).count()
    drafts_count = total_count - published_count
    page_numbers = _build_page_numbers(page, total_pages)
    
    return render_template(
        'contents_dashboard.html',
        contents=contents,
        total_count=total_count,
        published_count=published_count,
        drafts_count=drafts_count,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        has_prev=page > 1,
        has_next=page < total_pages,
        prev_page=page - 1,
        next_page=page + 1,
        page_numbers=page_numbers,
        current_page_count=len(contents),
        format_datetime_iso=format_datetime_iso
    )


def _build_page_numbers(current_page, total_pages):
    if total_pages <= 5:
        return list(range(1, total_pages + 1))
    start = max(1, current_page - 2)
    end = min(total_pages, current_page + 2)
    while (end - start) < 4:
        if start > 1:
            start -= 1
        elif end < total_pages:
            end += 1
        else:
            break
    return list(range(start, end + 1))

@app.route('/contents')
@login_required
@handle_db_errors
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    recent_contents = Content.query.filter_by(user_id=current_user.id).order_by(Content.created_at.desc()).limit(3).all()
    total_contents = Content.query.filter_by(user_id=current_user.id).count()
    
    # Check if account has expired
    is_expired = False
    if current_user.expires_at:
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        is_expired = current_user.expires_at < now_utc
    
    return render_template('user_dashboard.html', 
                         recent_contents=recent_contents,
                         total_contents=total_contents,
                         is_expired=is_expired)

@app.route('/contents/save', methods=['POST'])
@login_required
@handle_db_errors
def save_content():
    """Save AI-generated content directly"""
    try:
        title = request.form.get('title')
        content_text = request.form.get('content')
        purpose = request.form.get('purpose', '')
        writing_style = request.form.get('writing_style', '')
        audience = request.form.get('audience', '')
        keywords = request.form.get('keywords', '')
        hashtags = request.form.get('hashtags', '')
        cta = request.form.get('cta', '')
        negative_constraints = request.form.get('negative_constraints', '')
        reference_links = request.form.get('reference_links', '[]')
        
        if not title or not content_text:
            return jsonify({'error': 'Title and content are required'}), 400
        
        content = Content(
            user_id=current_user.id,
            title=title,
            content=content_text,
            purpose=purpose,
            writing_style=writing_style,
            audience=audience,
            keywords=keywords,
            hashtags=hashtags,
            cta=cta,
            negative_constraints=negative_constraints,
            reference_links=reference_links
        )
        db.session.add(content)
        db.session.commit()
        
        # Return content data for frontend update
        content_data = {
            'id': content.id,
            'title': content.title,
            'content': content.content,
            'purpose': content.purpose,
            'created_at': content.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify({
            'success': True, 
            'message': 'Content saved successfully',
            'content': content_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/contents/<int:content_id>/toggle-publish', methods=['POST'])
@login_required
def toggle_publish_status(content_id):
    """Toggle the published status of a content"""
    try:
        content = db.session.get(Content, content_id)
        
        if not content or content.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Content not found'}), 404
        
        # Get the new published status from request
        data = request.get_json()
        new_status = data.get('published', False)
        
        # Update the published status
        content.published = new_status
        db.session.commit()
        
        return jsonify({
            'success': True,
            'published': content.published,
            'message': 'Content status updated successfully'
        })
        
    except Exception as e:
        logging.error(f"Error toggling publish status: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/contents/<int:content_id>', methods=['GET'])
@login_required
def get_content_api(content_id):
    """Get content details via API"""
    try:
        content = db.session.get(Content, content_id)
        
        if not content or content.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Content not found'}), 404
        
        return jsonify({
            'success': True,
            'content': {
                'id': content.id,
                'title': content.title,
                'content': content.content,
                'purpose': content.purpose,
                'writing_style': content.writing_style,
                'audience': content.audience,
                'keywords': content.keywords,
                'hashtags': content.hashtags,
                'cta': content.cta,
                'negative_constraints': content.negative_constraints,
                'reference_links': content.reference_links,
                'published': content.published,
                'created_at': format_datetime_iso(content.created_at),
                'updated_at': format_datetime_iso(content.updated_at)
            }
        })
        
    except Exception as e:
        logging.error(f"Error getting content: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/contents/<int:content_id>/delete', methods=['DELETE'])
@login_required
def delete_content(content_id):
    content = db.session.get(Content, content_id)
    if not content or content.user_id != current_user.id:
        return jsonify({'error': 'Content not found'}), 404
    
    # Delete associated image file if exists
    if content.image_path and os.path.exists(content.image_path):
        try:
            os.remove(content.image_path)
        except Exception:
            pass
    
    db.session.delete(content)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Content deleted successfully'})

@app.route('/api/contents/<int:content_id>/update', methods=['POST'])
@login_required
def update_content_api(content_id):
    """Update content via API"""
    try:
        content = db.session.get(Content, content_id)
        
        if not content or content.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Content not found'}), 404
        
        data = request.get_json()
        title = data.get('title', '').strip()
        content_text = data.get('content', '').strip()
        
        if not title or not content_text:
            return jsonify({'success': False, 'error': 'Title and content are required'}), 400
        
        content.title = title
        content.content = content_text
        content.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Content updated successfully'
        })
        
    except Exception as e:
        logging.error(f"Error updating content: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/update-api-key', methods=['POST'])
@login_required
def update_api_key():
    """Allow authenticated users to update their Gemini API key."""
    try:
        data = request.get_json() or {}
        api_key = (data.get('apiKey') or '').strip()

        if not api_key:
            return jsonify({'success': False, 'error': 'API key is required.'}), 400

        if len(api_key) > 512:
            return jsonify({'success': False, 'error': 'API key is too long.'}), 400

        user = db.session.get(User, current_user.id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found.'}), 404

        user.api_key = api_key
        db.session.commit()

        logging.info(f"User {user.email} updated their API key")
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error updating API key: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to update API key.'}), 500


@app.route('/generate-content', methods=['POST'])
@login_required
def generate_content():
    try:
        logging.info("Generate content request received")
        # Check if user has API key (required for content generation)
        if not current_user.api_key:
            if current_user.is_admin:
                logging.error("Admin user has no API key configured")
                return jsonify({'error': 'Admin users need to provide a Gemini API key to generate content. Please update your profile or login again with an API key.'}), 400
            else:
                logging.error("User has no API key configured")
                return jsonify({'error': 'Please login with your Gemini API key to generate content.'}), 400
        
        # Configure Gemini with user's API key
        try:
            genai.configure(api_key=current_user.api_key)
            user_model = genai.GenerativeModel('gemini-2.5-flash')
            logging.info("User's Gemini API configured successfully")
        except Exception as api_error:
            logging.error(f"Error configuring user's API key: {api_error}")
            return jsonify({'error': 'Invalid API key. Please check your Gemini API key.'}), 400
        
        # Check if user account has expired (skip for admin users)
        if not current_user.is_admin:
            if current_user.expires_at:
                # Get current time in UTC
                now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                
                # Check if account has expired
                if current_user.expires_at < now_utc:
                    logging.warning(f"User {current_user.email} attempted to generate content with expired account")
                    return jsonify({
                        'error': 'Your account has expired. Please contact the administrator to renew your subscription.'
                    }), 403
        
        # request.form is used for multipart/form-data
        data = request.form
        page_name = data.get('pageName', '')
        prompt = data.get('prompt', '')
        purpose = data.get('purpose', '')
        
        # Validate required fields
        if not page_name.strip():
            return jsonify({'error': 'Page Name လိုအပ်ပါတယ်။ Facebook™️ Page သို့မဟုတ် Brand အမည် ထည့်ပါ။'}), 400
        
        if not prompt.strip():
            return jsonify({'error': 'Topic လိုအပ်ပါတယ်။ Content ၏ အဓိက အကြောင်းအရာ ထည့်ပါ။'}), 400
        writing_style = data.get('writingStyle', '')
        audience = data.get('audience', '')
        word_count = data.get('wordCount', '')
        keywords = data.get('keywords', '')
        hashtags = data.get('hashtags', '')
        cta = data.get('cta', '')
        negative_constraints = data.get('negativeConstraints', '')
        language = data.get('language', 'myanmar')
        
        # Get reference links
        reference_links_json = data.get('referenceLinks', '[]')
        try:
            reference_links = json.loads(reference_links_json) if reference_links_json else []
        except:
            reference_links = []
        
        # Get emoji toggle state
        include_emojis = data.get('includeEmojis', 'true').lower() == 'true'

        # Set language instruction
        language_instructions = {
            'myanmar': "The response must be in the Burmese (Myanmar) language.",
            'english': "The response must be in English."
        }
        language_instruction = language_instructions.get(language, "The response must be in the Burmese (Myanmar) language.")

        # Construct reference links section
        reference_section = ""
        if reference_links:
            reference_section = f"\nReference Links (use these as inspiration and reference):\n"
            for i, link in enumerate(reference_links, 1):
                reference_section += f"{i}. {link}\n"
            reference_section += "\nPlease use the information from these links as reference to create more relevant and informed content."

        # Construct emoji instruction based on toggle and word count
        emoji_instruction = ""
        if include_emojis:
            # Dynamic emoji count based on word count
            word_count_int = int(word_count) if word_count.isdigit() else 300
            if word_count_int <= 100:
                emoji_count = "1-2"
            elif word_count_int <= 200:
                emoji_count = "2-4"
            else:
                emoji_count = "3-6"
            
            emoji_instruction = f"\n\nIMPORTANT: Include appropriate emojis naturally throughout the content to make it more engaging and visually appealing. Use emojis that are relevant to the topic and context, but don't overuse them - aim for {emoji_count} well-placed emojis for this {word_count_int}-word post."
        else:
            emoji_instruction = "\n\nIMPORTANT: Do NOT include any emojis in the content. Generate clean text content without any emoji symbols."

        # Content style examples for each purpose type
        content_style_examples = {
            'informative': """
EXAMPLE REFERENCE (Follow this style and format):
---
MOT Genius Auto Writer: Content Generator တွေထဲက ထူးခြားတဲ့ ရွေးချယ်မှု 🎉

Content Creation လောကမှာ အချိန်ကုန်သက်သာပြီး အရည်အသွေးမြင့်တဲ့ စာသားတွေ ထွက်ဖို့ဆိုတာ ခက်ခဲတဲ့အလုပ်တစ်ခုပါ။ ဒါပေမဲ့ MOT က ဖန်တီးထားတဲ့ "Genius Auto Writer" ဆိုတဲ့ Content Generator က ဒီအခက်အခဲတွေကို ဖြေရှင်းပေးနိုင်တဲ့ အဖြေတစ်ခု ဖြစ်လာပါတယ်။

Genius Auto Writer ရဲ့ အားသာချက်တွေက ဘာတွေလဲ? 🤔

၁။ အချိန်တိုအတွင်း Content ထွက်ခြင်း: စီးပွားရေးလုပ်ငန်းတွေ၊ Content Creator တွေအတွက် အရေးကြီးဆုံးက အချိန်ပါ။ Genius Auto Writer ဟာ မိနစ်ပိုင်းအတွင်းကိုပဲ ကိုယ်လိုချင်တဲ့ Format နဲ့ Content အရှည်တစ်ခုကို ထုတ်ပေးနိုင်ပါတယ်။

၂။ Purpose အမျိုးမျိုးနဲ့ ရွေးချယ်နိုင်ခြင်း: information ပေးချင်တာလား၊ ကိုယ့် brand ကို ကြေညာချင်တာလား၊ စတဲ့ Content ပုံစံ အမျိုးမျိုးအတွက် ကြိုတင်ပြင်ဆင်ထားတဲ့ Template တွေ အများကြီး ပါဝင်ပါတယ်။

၃။ Plagiarism ကင်းစင်တဲ့ Content: ဒီ Generator ရဲ့ စနစ်ဟာ ရှိပြီးသား စာတွေကို ကူးယူတာမျိုး မဟုတ်ဘဲ၊ သတ်မှတ်ထားတဲ့ စည်းမျဉ်းတွေနဲ့ စာသားတည်ဆောက်ပုံ (Structure) ကို အသုံးပြုပြီး စာသားအသစ်တွေကို စီစဉ်ဖွဲ့စည်းတာ ဖြစ်တဲ့အတွက် ထွက်လာတဲ့ Content တွေဟာ Unique ဖြစ်ပြီး Plagiarism ကင်းပါတယ်။

Content Creator တစ်ယောက်အတွက် အခြေခံ Content တွေကို မြန်မြန်ဆန်ဆန် ဖန်တီးချင်တယ်ဆိုရင် Genius Auto Writer ဟာ တကယ်ကို အားကိုးရတဲ့ tool တစ်ခု ဖြစ်ပါတယ်။ 💡✍️

#ContentGenerator #GeniusAutoWriter #ContentMarketing
---
""",
            'engagement': """
EXAMPLE REFERENCE (Follow this style and format):
---
Content အမြန်လိုနေတဲ့ သူတွေ လက်တွေ့ကြုံဖူးတဲ့ အခက်အခဲများ! 😩

တစ်ခါတလေကျရင် Content Idea တွေက ဦးနှောက်ထဲမှာ ပြည့်ကျပ်နေပြီး လက်တွေ့ စာရေးတဲ့အခါ စကားလုံးတွေ တောင့်တင်း နေဖူးလား? ဒါမှမဟုတ် အချိန်က မရှိနေလို့ အရေးကြီးတဲ့ Post တစ်ခုကို အလျင်စလို ရေးလိုက်ရလို့ Quality ကျသွားဖူးလား? 🤔

အထူးသဖြင့် စီးပွားရေးလုပ်ငန်းရှင်တွေ၊ Freelance Writer တွေနဲ့ Social Media ကို နေ့စဉ်သုံးနေရသူတွေဆိုရင် ဒီလို စိန်ခေါ်မှုတွေကို မကြာခဏ ရင်ဆိုင်ရမှာပါ။

👉 ဒီလို အချိန်ကုန်သက်သာစေဖို့၊ စာရေးအားကို မြှင့်တင်ပေးဖို့ MOT က Genius Auto Writer ဆိုတဲ့ Content Generator Tool ကို ဖန်တီးထားတာပါ။ 💥

ဒါဆို ကျွန်တော်တို့ သိချင်တာလေး မေးကြည့်ပါရစေ...

၁။ Genius Auto Writer ဆိုတဲ့ Content Generator က Content Creation Workflow ကို ဘယ်လောက်အထိ မြန်စေမယ်လို့ ထင်ပါသလဲ? 🚀

၂။ ဒီလို Tool ကိုသုံးတဲ့အခါ Content Quality ပိုင်းကို စိုးရိမ်မိတာမျိုး ရှိပါသလား? ဘယ်အချက်ကို အဓိကထားပြီး စစ်ဆေးဖြစ်မလဲ? 🧐

၃။ အမြန်ဆုံး ရေးချင်တဲ့ Content အမျိုးအစား (ဥပမာ- Product Description, Caption, Blog Outline) က ဘာလဲ?

ကိုယ်တိုင် ကြုံတွေ့နေရတဲ့ အတွေ့အကြုံတွေ၊ Genius Auto Writer အပေါ် အမြင်တွေကို Comment မှာ ဝေမျှပေးခဲ့ဦးနော်။ 👇💬

#ContentLife #WriterStruggle #MOTGenius
---
""",
            'sales': """
EXAMPLE REFERENCE (Follow this style and format):
---
အချိန်မရှိဘူးလား? Content အရည်အသွေး ကျမှာကို စိုးရိမ်နေလား? 😱

Business အတွက်ဖြစ်ဖြစ်၊ Personal Brand အတွက်ဖြစ်ဖြစ်... Social Media မှာ နေ့တိုင်း Content တင်နေရတာဟာ အချိန်ကုန်၊ လူပင်ပန်း တဲ့ အလုပ်တစ်ခုပါ။ Blog Post တစ်ခုရေးဖို့ နာရီပေါင်းများစွာ ပေးရတယ်။ Product Caption ကောင်းကောင်းတစ်ခု ဖန်တီးဖို့ စကားလုံးတွေ ရှာဖွေနေရတယ်။ 😓

ဒါတွေ အားလုံးကို ဖြေရှင်းပေးမယ့် ကျွန်တော်တို့ MOT ရဲ့ "Content Generation Tool လေးတစ်ခုကို မိတ်ဆက်ပေးပါရစေ! 🚀

Genius Auto Writer ကို ဘာလို့ သုံးသင့်လဲ? (ရလဒ်တွေကိုပဲ ကြည့်ပါ!)

✅ Content ထုတ်လုပ်မှု 5X အထိ မြန်ဆန်လာမယ်:
Blog Outline၊ Email Header၊ Sales Copy၊ Facebook™️ Ad Caption တွေအတွက် စက္ကန့်ပိုင်းအတွင်း Professional Draft တွေ ရလာမယ်။

✅ Plagiarism ကင်းစင်တဲ့ Original Content:
ကျွန်တော်တို့ရဲ့ Tool ဟာ ရှိပြီးသားစာတွေကို ကူးယူတာ မဟုတ်ဘဲ၊ User သတ်မှတ်ချက်အတိုင်း စာသားဖွဲ့စည်းပုံစည်းမျဉ်းတွေ (Rule-Based Structure) နဲ့ စာသားအသစ်တွေကို စနစ်တကျ ပြန်စီပေးတာကြောင့် Content တွေဟာ Unique ဖြစ်ပါတယ်။

✅ SEO/Sales အတွက် Targeting စွမ်းအား မြင့်မားမယ်:
ကိုယ်ထည့်လိုက်တဲ့ Keywords တွေ၊ ရောင်းချမယ့် Product ရဲ့ အချက်အလက်တွေနဲ့ ကိုက်ညီတဲ့ စာသားတွေကို တိတိကျကျ ဖန်တီးပေးတာကြောင့် ထွက်လာတဲ့ Content တွေဟာ Target Audience ကို ဆွဲဆောင်ဖို့ ပိုမို ထိရောက်တယ်။ 🎯

အခုပဲ Genius Auto Writer ကို စတင် အသုံးပြုပြီး Content Marketing ကို နောက်တစ်ဆင့် တက်လှမ်းလိုက်ပါ။ 👇

#SalesCopy #ContentGenerator #DigitalMarketingTool
---
""",
            'emotional': """
EXAMPLE REFERENCE (Follow this style and format):
---
စာရေးချင်စိတ် အပြည့်နဲ့ ကွန်ပျူတာရှေ့ ထိုင်ချလိုက်ပေမဲ့... Screen က အလွတ်အတိုင်းပဲ ကျန်နေတဲ့အခါ ဘယ်လိုခံစားရလဲ? 😩

စိတ်ကူးတွေက ရင်ထဲမှာ အစီအရီရှိနေတယ်။ ဒီနေ့ ဘာတင်ရမယ်၊ ဘယ်လို Message ပေးရမယ်ဆိုတာလည်း သိတယ်။ ဒါပေမဲ့ လက်တွေ့ စာလုံးပေါင်းပြီး ရေးရတော့မယ့်အချိန်မှာ "ဘယ်ကနေ စရမလဲ" ဆိုတဲ့ မေးခွန်းက ကိုယ့်ကို အားအင်ကုန်ခမ်းစေတယ်။ 😔

တစ်ခါတလေကျရင် ဒီလို အချိန်တွေကြောင့် Quality ကောင်းတဲ့ Content မထုတ်နိုင်ဘဲ "ဒီတစ်ခါတော့ ဒီအတိုင်းပဲ တင်လိုက်တော့မယ်" ဆိုပြီး လက်လျှော့လိုက်ရတာမျိုးတွေ မကြာခဏ ကြုံဖူးမှာပါ။

ကျွန်တော်တို့ MOT အဖွဲ့သားတွေ ဒီခံစားချက်ကို နားလည်ပြီး လုပ်ငန်းရှင်တွေရဲ့ စိတ်ကူးတွေ ပျောက်ဆုံးမသွားစေဖို့ Genius Auto Writer ကို ဖန်တီးခဲ့တာဖြစ်ပါတယ်။ 💡

"မရေးနိုင်ဘူး" ဆိုတဲ့ ဝန်ထုပ်ဝန်ပိုးကို လွှတ်ချလိုက်ပါ။ ကိုယ့်ရဲ့ စိတ်ကူးတွေကို လွတ်လပ်စွာ စီးဆင်းခွင့်ပေးပြီး Genius Auto Writer ရဲ့ စွမ်းအားနဲ့ တွဲဖက်လိုက်ပါ။ 💖✍️

#CreativeStruggles #StorytellingTool #ContentQuality
---
""",
            'announcement': """
EXAMPLE REFERENCE (Follow this style and format):
---
🔥 Content Revolution ၏ အစ: Genius Auto Writer Launch Event! 🔥

Content Marketing လောကကို လှုပ်ခတ်စေမယ့်၊ Content ရေးသားခြင်း နည်းလမ်းတွေကို လုံးဝပြောင်းလဲပစ်မယ့် tool အသစ်တစ်ခု မိတ်ဆက်ပွဲကို MOT ကနေ ခမ်းနားစွာ ကျင်းပတော့မှာ ဖြစ်ပါတယ်။

အချိန်ကုန်ခံပြီး အားထုတ်စိုက်ထုတ်နေရတဲ့ Content ရေးသားမှုတွေ၊ Idea ညှစ်ထုတ်ရတဲ့ နေ့ရက်တွေကို ရပ်တန့်ဖို့ အချိန်တန်ပါပြီ။ အခုဆိုရင် Content Quality အကောင်းဆုံးနဲ့ Facebook™️ Page မှာ ချက်ချင်းယူသုံးလို့ရတဲ့ Post တွေကို စက္ကန့်ပိုင်းအတွင်း ဖန်တီးပေးနိုင်တဲ့ Genius Auto Writer ရဲ့ စွမ်းဆောင်ရည်တွေကို ကိုယ်တိုင် မြင်တွေ့ရမယ့် ပွဲပါ။

🎯 ဘာလို့ ဒီပွဲကို မဖြစ်မနေ လာရောက်သင့်လဲ?

✅ MOT ရဲ့ Smart Content Engine တစ်ခုဖြစ်တဲ့ Genius Auto Writer ဟာ တော်ရုံ Content Generator တွေလို AI စနစ်ကို အခြေခံပြီး ရေးထားတာမျိုး မဟုတ်ပါဘူး။ Content Writer ဝါရင့်တွေရဲ့ အောင်မြင်ပြီးသား ရောင်းအားတက် နည်းစနစ်တွေ၊ စိတ်ပညာပေါ် အခြေခံတဲ့ စာသား Framework တွေကို ပေါင်းစပ်တည်ဆောက်ထားတာ ဖြစ်ပါတယ်။

✅ တကယ့်စွမ်းဆောင်ရည်ကို ကိုယ်တိုင်တွေ့ရမယ်: Content Writer ငှားစရာမလိုဘဲ၊ စျေးကြီးပေးပြီး Agency ကိုအပ်စရာမလိုဘဲ Content Quality အမြင့်ဆုံးတွေကို ဘယ်လို ထုတ်ယူနိုင်လဲဆိုတာကို Live Demo ပြသသွားမှာပါ။

✅ Business Opportunity: Content အတွက် အချိန်ကုန်၊ လူကုန် မခံချင်တဲ့ Business Owner တွေ၊ Marketer တွေအတွက် တစ်လလုံး Content အကန့်အသတ်မရှိ ထုတ်နိုင်မယ့် ဒီ Tool ကို ဘယ်လို အကျိုးရှိရှိ သုံးနိုင်မလဲဆိုတဲ့ Business Strategy တွေကိုပါ မျှဝေပေးသွားမှာပါ။

✅ Q&A Session: Genius Auto Writer နဲ့ပတ်သက်ပြီး သိချင်တာတွေ၊ စိတ်ဝင်စားတာတွေကို တိုက်ရိုက်မေးမြန်းနိုင်မယ့် အခွင့်အရေး ရရှိမှာပါ။

📅 ပွဲကျင်းပမည့် နေ့ရက်နှင့် အချိန်:
2025 ခုနှစ်၊ နိုဝင်ဘာလ ၁၀ ရက် (တနင်္လာနေ့)
နံနက် ၁၀ နာရီ မှ နေ့လယ် ၁၂ နာရီအထိ

📌 နေရာ:
(ရန်ကုန်မြို့ရှိ TBD ခန်းမအမည် / Online Webinar ဆိုပါက Zoom Link ကို ဖော်ပြပါမည်)

Content Marketing မှာ ပြိုင်ဘက်တွေထက် တစ်လှမ်းသာချင်သူတွေ၊ Content ရေးသားမှုအတွက် စိန်ခေါ်နေသူတွေ ဒီအခွင့်အရေးကို လက်မလွတ်သင့်ပါဘူး။

ပွဲတက်ရောက်ရန် စိတ်ဝင်စားပါက Messenger မှာ "Launch" လို့ စာတိုပေးပို့ပြီး အမြန်ဆုံး ကြိုတင်စာရင်းပေးလိုက်ပါ။

#GeniusAutoWriterLaunch
#MOT
#ContentGenerator
#EventAnnouncement
#MyanmarBusiness
#DigitalMarketingMyanmar
#ContentStrategy
#NewProduct
---
""",
            'educational': """
EXAMPLE REFERENCE (Follow this style and format):
---
📣 Content ရေးသားမှုကို အဆင့်မြှင့်တင်ဖို့ Genius Auto Writer ကို ဘယ်လို ထိထိရောက်ရောက် သုံးမလဲ? (Step-by-Step Guide) 💡

Page အတွက် Quality ကောင်းတဲ့ Content တွေကို အချိန်ကုန်သက်သာစွာ ထုတ်ယူချင်သူတွေအတွက် MOT ရဲ့ "Genius Auto Writer" Content Generator ဟာ အကောင်းဆုံး tool တစ်ခုပါ။

Genius Auto Writer အသုံးပြုနည်း အဆင့် (၃) ဆင့်:

အဆင့် ၁။ Content Purpose ကို ရွေးပါ 🎯

Genius Auto Writer ကို စတင်အသုံးပြုတာနဲ့ အရင်ဆုံး သင့် Content ရဲ့ ရည်ရွယ်ချက် (Purpose) ကို ရွေးချယ်ပေးရပါမယ်။

• ကြော်ငြာ/Promotion: ပစ္စည်းအသစ် မိတ်ဆက်တာ၊ Discount ပေးတာမျိုးတွေအတွက်။
• Engagement: Comment, Like, Share များဖို့ မေးခွန်းထုတ်တာ၊ ဂိမ်းဆော့ခိုင်းတာမျိုး။
• Announcement/Update: သတင်း၊ အစီအစဉ် အသစ်တွေ ကြေညာဖို့။

အဆင့် ၂။ Key Information တွေကို ထည့်သွင်းပါ ⌨️

ဒါက အရေးအကြီးဆုံး အပိုင်းပါ။ သင်ထုတ်ယူချင်တဲ့ Content နဲ့ ပတ်သက်တဲ့ အချက်အလက် (Key Information) တွေကို တိတိကျကျ ရိုက်ထည့်ပေးရပါမယ်။

• ထုတ်ကုန်/ဝန်ဆောင်မှု နာမည်: (ဥပမာ: MOT Digital Course)
• ထူးခြားချက်/အကျိုးကျေးဇူး: (ဥပမာ: တစ်လအတွင်း Sale တက်စေမယ့် နည်းဗျူဟာ)
• Target Audience: (ဥပမာ: အွန်လိုင်းစီးပွားရေး လုပ်ငန်းရှင်များ)

အဆင့် ၃။ Generate ကို နှိပ်ပြီး ချက်ချင်း အသုံးပြုပါ ✅

အဆင့် (၁) နဲ့ (၂) မှာ လိုအပ်တဲ့ အချက်အလက်တွေ ဖြည့်ပြီးတာနဲ့ "Generate" ခလုတ်ကို နှိပ်လိုက်ပါ။ စက္ကန့်ပိုင်းအတွင်းမှာ Facebook™️ Page မှာ တိုက်ရိုက်ယူသုံးလို့ရတဲ့ Content ကို ရရှိပါလိမ့်မယ်။

#ContentWritingTips #DigitalMarketingMyanmar #GeniusAutoWriter
---
""",
            'showcase': """
EXAMPLE REFERENCE (Follow this style and format):
---
⚡️ Content ရေးသားမှုကို စက္ကန့်ပိုင်းအတွင်း အပြီးသတ်ပေးမယ့် Genius Auto Writer ရဲ့ Live Demo! 🚀

Page Admin တွေ၊ Content Creator တွေ စိတ်ပူနေရတဲ့ "Content Quality" နဲ့ "အချိန်ကုန်သက်သာမှု" ဆိုတဲ့ ပြဿနာနှစ်ခုကို MOT ရဲ့ Genius Auto Writer နဲ့ ဘယ်လို ဖြေရှင်းနိုင်လဲဆိုတာ ဒီနေ့ လက်တွေ့ပြသသွားပါမယ်။

Genius Auto Writer က AI စနစ်မဟုတ်ဘဲ၊ Content ပညာရှင်တွေရဲ့ ရေးသားမှုပုံစံနဲ့ Facebook™️ Trend တွေကို အခြေခံပြီး တည်ဆောက်ထားတဲ့ MOT ရဲ့ ကိုယ်ပိုင် Generator ဖြစ်ပါတယ်။

Genius Auto Writer ရဲ့ 'Premium Quality' Output ကို ကြည့်လိုက်ပါ! 👀

ဥပမာအနေနဲ့၊ ကျွန်တော်တို့ရဲ့ Product အသစ်ဖြစ်တဲ့ 'MOT Sales Booster Course' အတွက် Promotion Content တစ်ခု လိုချင်တယ်ဆိုပါစို့။

Inputs (ထည့်သွင်းရမယ့် အချက်အလက်များ):

1. Content Purpose: Promotion / Course Sales
2. Product Name: MOT Sales Booster Course
3. Key Benefits:
   • တစ်ပတ်အတွင်း Sales 100% တက်စေမယ့် လျှို့ဝှက်ချက်
   • Target Audience ကို စနစ်တကျ ရှာဖွေနည်း
   • လက်တွေ့ အကောင်အထည်ဖော်ရုံပဲ လိုတဲ့ Practical Strategy တွေ

Output (Genius Auto Writer က ထုတ်ပေးမယ့် Content ပုံစံ):

✨ ခေါင်းစဉ်: ❌ Sale တွေကျလို့ စိတ်ညစ်မနေပါနဲ့! ၇ ရက်အတွင်း ၁၀၀% တိုးတက်စေမယ့် လျှို့ဝှက်ချက်!

📈 စာကိုယ် (Body):
Online Business လုပ်ငန်းရှင်တွေအတွက် Sale ပိုတက်ဖို့ ခေါင်းစားနေရပြီလား? MOT Sales Booster Course ကို စတင်လိုက်ပါ။ ဒီ Course က တခြား Course တွေလို သီအိုရီတွေချည်း မဟုတ်ဘဲ၊ လက်တွေ့အသုံးချနိုင်မယ့် Practical Strategy တွေကိုပဲ အဓိကထား သင်ပေးမှာပါ။

➡️ CTA: အချိန်မဆွဲပါနဲ့၊ ဒီနေ့ပဲ စာရင်းသွင်းပြီး သင်တန်းကြေး Discount ရယူလိုက်ပါ။

#GeniusAutoWriterDemo #MOTTech #ContentTool #ProductShowcase
---
"""
        }
        
        # Get the example for the selected purpose
        style_example = content_style_examples.get(purpose, "")

        # Construct a more detailed prompt with style example reference
        enhanced_prompt = f"""You are a 10 years experience social media content writer. Directly generate a social media post. Do not include any introductory phrases, explanations, or preambles. {language_instruction}{emoji_instruction}

{style_example}

IMPORTANT: Use the example above as a REFERENCE for style, format, structure, and tone. DO NOT copy the example content. Create NEW and ORIGINAL content based on the topic and requirements below, but follow the same writing style, formatting patterns, and engagement approach shown in the example.

Page/Brand Name: {page_name}
Topic: {prompt}
Purpose: {purpose}
Writing Style: {writing_style}
Target Audience: {audience}
Word Count: Approximately {word_count} words
Keywords to include: {keywords}
Hashtags to include: {hashtags}
Call to Action: {cta}
Avoid/Don't include: {negative_constraints}{reference_section}
        """
        
        # Check for an uploaded image
        image_file = request.files.get('image')
        logging.info(f"Request files: {list(request.files.keys())}")
        logging.info(f"Image file: {image_file}, filename: {image_file.filename if image_file else 'None'}")
        
        if image_file and image_file.filename:
            # Check file size (limit to 4MB for better compatibility)
            image_file.stream.seek(0, 2)  # Seek to end
            file_size = image_file.stream.tell()
            image_file.stream.seek(0)  # Reset to beginning
            
            logging.info(f"Image file received: {image_file.filename}, size: {file_size} bytes")
            
            # Check if file is too large (4MB limit for better compatibility)
            if file_size > 4 * 1024 * 1024:  # 4MB
                logging.warning(f"Image file too large: {file_size} bytes")
                return jsonify({'error': f'ပုံဖိုင်က အရမ်းကြီးလွန်းပါတယ်။ 4MB ထက်နည်းတဲ့ ပုံကို သုံးပါ။ သင့်ဖိုင်က {file_size / (1024*1024):.1f}MB ရှိပါတယ်။'}), 400
            
            try:
                # Reset stream position to beginning
                image_file.stream.seek(0)
                img = PIL.Image.open(image_file.stream)
                
                # Resize image if it's too large (max 1536x1536 for better quality)
                max_size = (1536, 1536)
                if img.size[0] > max_size[0] or img.size[1] > max_size[1]:
                    logging.info(f"Resizing image from {img.size} to fit {max_size}")
                    img.thumbnail(max_size, PIL.Image.Resampling.LANCZOS)
                
                # Convert to RGB if necessary
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Combine the text prompt and the image for the model
                contents = [enhanced_prompt, img]
                logging.info("Sending prompt and image to Gemini.")
                response = user_model.generate_content(contents)
            except Exception as img_error:
                logging.error(f"Error processing image: {img_error}")
                # Fall back to text-only if image processing fails
                logging.info("Falling back to text-only prompt due to image error.")
                response = user_model.generate_content(enhanced_prompt)
        else:
            # If no image, proceed with text only
            logging.info("Sending text-only prompt to Gemini.")
            response = user_model.generate_content(enhanced_prompt)

        # Ensure response has text content
        if hasattr(response, 'text') and response.text:
            # Apply Facebook trademark processing to generated content
            processed_content = add_facebook_trademark(response.text)
            return jsonify({'content': processed_content})
        else:
            logging.error("Gemini response has no text content")
            return jsonify({'error': 'Failed to generate content. Please try again.'}), 500
            
    except Exception as e:
        logging.error(f"Error in generate_content: {e}")
        # Ensure error response is always valid JSON
        error_message = str(e)
        if len(error_message) > 200:  # Truncate very long error messages
            error_message = error_message[:200] + "..."
        return jsonify({'error': error_message}), 500
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/favicon.ico')
def favicon():
    response = send_from_directory(os.path.join(app.root_path, 'static', 'images'), 'MOT.d21a8f07.png', mimetype='image/png')
    # Force no cache to always serve fresh favicon
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['ETag'] = f'favicon-v{app.config.get("FAVICON_VERSION", "2.0")}-{hash(str(__import__("time").time()))}'
    return response

@app.route('/test-toast')
@login_required
def test_toast():
    """Test route to generate flash messages for toast testing"""
    flash('This is a test success message!', 'success')
    flash('This is a test error message!', 'error')
    flash('This is a test warning message!', 'warning')
    return redirect(url_for('user_dashboard'))

@app.route('/api/daily-cleanup', methods=['GET'])
def daily_cleanup():
    """Daily cron job to delete expired users from database (Vercel Cron)"""
    try:
        # No authentication needed - Vercel Cron is secure by default
        
        current_time = datetime.now(timezone.utc)
        
        # Delete expired users (both trial and normal)
        expired_users = User.query.filter(
            User.expires_at.isnot(None),
            User.expires_at <= current_time,
            User.is_admin == False
        ).all()
        
        deleted_count = 0
        deleted_emails = []
        
        for user in expired_users:
            deleted_emails.append(user.email)
            logging.info(f"Vercel cron cleanup: Deleting expired user: {user.email} (expired at: {user.expires_at})")
            db.session.delete(user)
            deleted_count += 1
        
        if deleted_count > 0:
            db.session.commit()
            logging.info(f"Vercel cron: Successfully deleted {deleted_count} expired user accounts")
        
        return jsonify({
            'success': True,
            'message': f'Vercel cron cleanup completed',
            'deleted_count': deleted_count,
            'deleted_users': deleted_emails,
            'timestamp': current_time.isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error in Vercel cron cleanup: {e}")
        db.session.rollback()
        return jsonify({'error': 'Vercel cron cleanup failed', 'details': str(e)}), 500

def create_admin_user():
    """Create default admin user if none exists"""
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@gmail.com')
    admin_password = os.getenv('ADMIN_PASSWORD')
    
    if not admin_password:
        logging.warning("ADMIN_PASSWORD not set in environment variables. Skipping admin user creation.")
        return
    
    # Check if admin user already exists by email
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        password_hash = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin = User(
            email=admin_email,
            password_hash=password_hash,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        logging.info(f"Admin user created: email='{admin_email}'")
    else:
        logging.info(f"Admin user already exists: {admin_email}")

def reset_database():
    """Drop all tables and recreate them - USE WITH CAUTION"""
    try:
        logging.warning("RESETTING DATABASE - ALL DATA WILL BE LOST!")
        db.drop_all()
        db.create_all()
        logging.info("Database reset complete - all tables recreated")
        return True
    except Exception as e:
        logging.error(f"Error resetting database: {e}")
        return False

def migrate_database():
    """Add email and api_key columns to user table, remove username column, and update content fields"""
    try:
        with db.engine.connect() as conn:
            # Add email column to user table if it doesn't exist
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='email'
            """))
            
            if not result.fetchone():
                logging.info("Adding email column to user table...")
                conn.execute(db.text("ALTER TABLE \"user\" ADD COLUMN email VARCHAR(120) UNIQUE"))
                conn.commit()
                logging.info("Email column added successfully")
            else:
                logging.info("Email column already exists")
            
            # Add api_key column to user table if it doesn't exist
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='api_key'
            """))
            
            if not result.fetchone():
                logging.info("Adding api_key column to user table...")
                conn.execute(db.text("ALTER TABLE \"user\" ADD COLUMN api_key TEXT"))
                conn.commit()
                logging.info("API key column added successfully")
            else:
                logging.info("API key column already exists")
            
            # Remove username column if it exists (after ensuring email is populated)
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='username'
            """))
            
            if result.fetchone():
                logging.info("Removing username column from user table...")
                conn.execute(db.text("ALTER TABLE \"user\" DROP COLUMN username"))
                conn.commit()
                logging.info("Username column removed successfully")
            else:
                logging.info("Username column already removed")
            
            # Add new fields to content table if they don't exist
            # Check for cta column
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='content' AND column_name='cta'
            """))
            
            if not result.fetchone():
                logging.info("Adding cta column to content table...")
                conn.execute(db.text("ALTER TABLE content ADD COLUMN cta VARCHAR(500)"))
                conn.commit()
                logging.info("CTA column added successfully")
            
            # Check for negative_constraints column
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='content' AND column_name='negative_constraints'
            """))
            
            if not result.fetchone():
                logging.info("Adding negative_constraints column to content table...")
                conn.execute(db.text("ALTER TABLE content ADD COLUMN negative_constraints TEXT"))
                conn.commit()
                logging.info("Negative constraints column added successfully")
            
            # Check for reference_links column
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='content' AND column_name='reference_links'
            """))
            
            if not result.fetchone():
                logging.info("Adding reference_links column to content table...")
                conn.execute(db.text("ALTER TABLE content ADD COLUMN reference_links TEXT"))
                conn.commit()
                logging.info("Reference links column added successfully")
            
            # Update content table columns to TEXT for unlimited length
            logging.info("Updating content table column types to TEXT...")
            conn.execute(db.text("ALTER TABLE content ALTER COLUMN purpose TYPE TEXT"))
            conn.execute(db.text("ALTER TABLE content ALTER COLUMN audience TYPE TEXT"))
            conn.execute(db.text("ALTER TABLE content ALTER COLUMN keywords TYPE TEXT"))
            conn.execute(db.text("ALTER TABLE content ALTER COLUMN hashtags TYPE TEXT"))
            conn.execute(db.text("ALTER TABLE content ALTER COLUMN cta TYPE TEXT"))
            conn.commit()
            logging.info("Column types updated to TEXT successfully")
            
            # Add content_count column to user table
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='content_count'
            """))
            
            if not result.fetchone():
                logging.info("Adding content_count column to user table...")
                conn.execute(db.text("ALTER TABLE \"user\" ADD COLUMN content_count INTEGER DEFAULT 0 NOT NULL"))
                conn.commit()
                logging.info("content_count column added successfully")
            
            # Add expires_at column to user table
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='expires_at'
            """))
            
            if not result.fetchone():
                logging.info("Adding expires_at column to user table...")
                conn.execute(db.text("ALTER TABLE \"user\" ADD COLUMN expires_at TIMESTAMP"))
                conn.commit()
                logging.info("expires_at column added successfully")
            
            # Add user_type column to user table
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='user_type'
            """))
            
            if not result.fetchone():
                logging.info("Adding user_type column to user table...")
                conn.execute(db.text("ALTER TABLE \"user\" ADD COLUMN user_type VARCHAR(20) DEFAULT 'normal'"))
                conn.commit()
                logging.info("user_type column added successfully")
            
            # Add subscription_duration column to user table
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='subscription_duration'
            """))
            
            if not result.fetchone():
                logging.info("Adding subscription_duration column to user table...")
                conn.execute(db.text("ALTER TABLE \"user\" ADD COLUMN subscription_duration VARCHAR(20)"))
                conn.commit()
                logging.info("subscription_duration column added successfully")
            
            # Add published column to content table
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='content' AND column_name='published'
            """))
            
            if not result.fetchone():
                logging.info("Adding published column to content table...")
                conn.execute(db.text("ALTER TABLE content ADD COLUMN published BOOLEAN DEFAULT FALSE NOT NULL"))
                conn.commit()
                logging.info("published column added successfully")
            
    except Exception as e:
        logging.error(f"Migration failed: {e}")
        raise e

# Initialize database function (called on first request)
def init_db():
    """Initialize database tables and admin user"""
    try:
        with app.app_context():
            db.create_all()
            migrate_database()
            create_admin_user()
            logging.info("Database tables created/updated.")
            logging.info("User deletion handled by Vercel Cron (/api/daily-cleanup).")
            logging.info(f"Using database: {DATABASE_URL.split('://')[0] if DATABASE_URL else 'No database URL'}")
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        # Don't raise error in production, just log it
        pass

# Initialize database when app starts (for production)
# Only run if not in serverless environment
if not os.getenv('VERCEL'):
    init_db()

# For serverless environments, initialize on first request
# Using before_request instead of deprecated before_first_request
_db_initialized = False

@app.before_request
def initialize_database():
    """Initialize database on first request in serverless environment"""
    global _db_initialized
    if os.getenv('VERCEL') and not _db_initialized:
        init_db()
        _db_initialized = True

if __name__ == '__main__':
    app.run(debug=True)
