from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length
import google.generativeai as genai
import PIL.Image
import logging

# Load environment variables from .env file
load_dotenv()

# Myanmar timezone (UTC+6:30)
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

UPLOAD_FOLDER = os.path.join(project_folder, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "a-very-secret-key-for-development")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['WTF_CSRF_ENABLED'] = True

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
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    locked_until = db.Column(db.DateTime, nullable=True)
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

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    purpose = db.Column(db.String(100), nullable=True)
    writing_style = db.Column(db.String(100), nullable=True)
    audience = db.Column(db.String(100), nullable=True)
    keywords = db.Column(db.String(500), nullable=True)
    hashtags = db.Column(db.String(500), nullable=True)
    image_path = db.Column(db.String(500), nullable=True)
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

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    is_admin = SelectField('Role', choices=[('False', 'User'), ('True', 'Admin')], default='False')
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
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash')

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
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            # Check if account is locked
            if user.is_account_locked():
                flash('Account is temporarily locked due to multiple failed login attempts. Please try again later.', 'error')
                return redirect(url_for('login', login_error='true', message='Account is temporarily locked due to multiple failed login attempts'))
            
            # Check if account is deactivated
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return redirect(url_for('login', login_error='true', message='Your account has been deactivated. Please contact an administrator'))
            
            # Check password
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                # Successful login - reset failed attempts
                user.reset_failed_attempts()
                login_user(user, remember=True)
                flash(f'Welcome back, {user.username}!', 'success')
                # Add URL parameter for toast notification
                return redirect(url_for('index', login_success='true', username=user.username))
            else:
                # Failed password - record attempt
                user.record_failed_login()
                remaining_attempts = 3 - user.failed_login_attempts
                
                if user.failed_login_attempts >= 3:
                    flash('Account deactivated due to 3 failed login attempts. Please contact an administrator.', 'error')
                    return redirect(url_for('login', login_error='true', message='Account deactivated due to 3 failed login attempts'))
                else:
                    flash(f'Invalid password. {remaining_attempts} attempts remaining before account deactivation.', 'error')
                    return redirect(url_for('login', login_error='true', message=f'Invalid password. {remaining_attempts} attempts remaining'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login', login_error='true', message='Invalid username or password'))
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash(f'Goodbye {username}! You have been logged out successfully.', 'success')
    # Add URL parameter for toast notification
    return redirect(url_for('login', logout_success='true', username=username))

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
        query = query.filter(User.username.contains(search))
    
    if filter_status == 'active':
        query = query.filter(User.is_active == True)
    elif filter_status == 'inactive':
        query = query.filter(User.is_active == False)
    
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    total_users = User.query.count()
    total_contents = Content.query.count()
    recent_contents = Content.query.order_by(Content.created_at.desc()).limit(5).all()
    
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
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        
        if existing_user:
            flash('Username already exists', 'error')
            return redirect(url_for('create_user', user_error='true', message='Username already exists'))
        else:
            password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                username=form.username.data,
                password_hash=password_hash,
                is_admin=(form.is_admin.data == 'True')
            )
            db.session.add(user)
            db.session.commit()
            flash(f'User {form.username.data} created successfully', 'success')
            # Add URL parameter for toast notification
            return redirect(url_for('admin_dashboard', user_created='true', username=form.username.data))
    
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
        print(f"User {user.username} (ID: {user_id}) {status} by admin {current_user.username}")
        
        return jsonify({
            'success': True, 
            'message': f'User {user.username} {status} successfully',
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
        
        print(f"Admin {current_user.username} reset failed attempts for user {user.username} (was: {old_attempts})")
        
        return jsonify({
            'success': True, 
            'message': f'Failed login attempts reset for {user.username}',
            'was_reactivated': not user.is_active and user.locked_until is not None
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting user attempts: {e}")
        return jsonify({'error': 'Database error occurred'}), 500

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
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    recent_contents = Content.query.filter_by(user_id=current_user.id).order_by(Content.created_at.desc()).limit(5).all()
    total_contents = Content.query.filter_by(user_id=current_user.id).count()
    
    return render_template('user_dashboard.html', 
                         recent_contents=recent_contents,
                         total_contents=total_contents)

@app.route('/contents')
@login_required
@handle_db_errors
def content_history():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    
    # Build query with search
    query = Content.query.filter_by(user_id=current_user.id)
    
    if search:
        query = query.filter(
            db.or_(
                Content.title.contains(search),
                Content.content.contains(search),
                Content.purpose.contains(search)
            )
        )
    
    contents = query.order_by(Content.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('content_history.html', contents=contents, search=search)

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
            hashtags=hashtags
        )
        db.session.add(content)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Content saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/contents/<int:content_id>')
@login_required
def view_content(content_id):
    content = db.session.get(Content, content_id)
    if not content or content.user_id != current_user.id:
        flash('Content not found', 'error')
        return redirect(url_for('content_history'))
    
    return render_template('view_content.html', content=content)

@app.route('/contents/<int:content_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_content(content_id):
    content = db.session.get(Content, content_id)
    if not content or content.user_id != current_user.id:
        flash('Content not found', 'error')
        return redirect(url_for('content_history'))
    
    if request.method == 'POST':
        content.title = request.form.get('title', content.title)
        content.content = request.form.get('content', content.content)
        content.purpose = request.form.get('purpose', content.purpose)
        content.writing_style = request.form.get('writing_style', content.writing_style)
        content.audience = request.form.get('audience', content.audience)
        content.keywords = request.form.get('keywords', content.keywords)
        content.hashtags = request.form.get('hashtags', content.hashtags)
        content.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Content updated successfully', 'success')
        return redirect(url_for('view_content', content_id=content.id))
    
    return render_template('edit_content.html', content=content)

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

@app.route('/generate-content', methods=['POST'])
@login_required
def generate_content():
    try:
        # request.form is used for multipart/form-data
        data = request.form
        prompt = data.get('prompt', '')
        purpose = data.get('purpose', '')
        writing_style = data.get('writingStyle', '')
        audience = data.get('audience', '')
        word_count = data.get('wordCount', '')
        keywords = data.get('keywords', '')
        hashtags = data.get('hashtags', '')
        copywriting_model = data.get('copywritingModel', 'none')

        model_instructions = {
            'AIDA': "using the AIDA (Attention, Interest, Desire, Action) framework",
            'PAS': "using the PAS (Problem, Agitate, Solution) framework",
            'FAB': "using the FAB (Features, Advantages, Benefits) framework",
            '4Ps': "using the 4 P's (Picture, Promise, Prove, Push) framework",
            'BAB': "using the BAB (Before, After, Bridge) framework",
            'none': ""
        }
        
        model_instruction = model_instructions.get(copywriting_model, "")

        # Construct a more detailed prompt
        enhanced_prompt = f"""You are a 10 years experience social media content writer. Directly generate a social media post {model_instruction}. Do not include any introductory phrases, explanations, or preambles. The response must be in the Burmese language.
        Topic: {prompt}
        Purpose: {purpose}
        Writing Style: {writing_style}
        Target Audience: {audience}
        Word Count: Approximately {word_count} words
        Keywords to include: {keywords}
        Hashtags to include: {hashtags}
        """
        
        # Check for an uploaded image
        image_file = request.files.get('image')
        
        if image_file:
            # If an image is present, use it for context
            logging.info(f"Image file received: {image_file.filename}")
            img = PIL.Image.open(image_file.stream)
            # Combine the text prompt and the image for the model
            contents = [enhanced_prompt, img]
            logging.info("Sending prompt and image to Gemini.")
            response = model.generate_content(contents)
        else:
            # If no image, proceed with text only
            logging.info("Sending text-only prompt to Gemini.")
            response = model.generate_content(enhanced_prompt)

        return jsonify({'content': response.text})
    except Exception as e:
        logging.error(f"Error in generate_content: {e}")
        return jsonify({'error': str(e)}), 500
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/test-toast')
@login_required
def test_toast():
    """Test route to generate flash messages for toast testing"""
    flash('This is a test success message!', 'success')
    flash('This is a test error message!', 'error')
    flash('This is a test warning message!', 'warning')
    return redirect(url_for('user_dashboard'))

def create_admin_user():
    """Create default admin user if none exists"""
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if not admin_password:
            logging.warning("ADMIN_PASSWORD not set in environment variables. Skipping admin user creation.")
            return
        
        password_hash = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin = User(
            username=admin_username,
            password_hash=password_hash,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        logging.info(f"Admin user created: username='{admin_username}'")

def migrate_database():
    """Remove email column if it exists"""
    try:
        with db.engine.connect() as conn:
            result = conn.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='user' AND column_name='email'
            """))
            
            if result.fetchone():
                logging.info("Removing email column from user table...")
                conn.execute(db.text("ALTER TABLE \"user\" DROP COLUMN IF EXISTS email"))
                conn.commit()
                logging.info("Email column removed successfully")
            else:
                logging.info("Email column does not exist, no migration needed")
    except Exception as e:
        logging.error(f"Migration failed: {e}")
        raise e

# Initialize database when app starts (for production)
with app.app_context():
    try:
        db.create_all()
        migrate_database()
        create_admin_user()
        logging.info("Database tables created/updated.")
        logging.info(f"Using database: {DATABASE_URL.split('://')[0]}")
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        # Don't raise error in production, just log it
        pass

if __name__ == '__main__':
    app.run(debug=True)
