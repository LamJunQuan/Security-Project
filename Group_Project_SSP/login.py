import base64
import traceback

from itsdangerous import URLSafeTimedSerializer
from pandas.io.sas.sas_constants import magic
from urllib.parse import urlencode
import datetime
import requests
from flask import Flask,render_template,request,redirect,url_for,session,flash,jsonify,abort,make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from werkzeug.utils import secure_filename
import os
from flask_bcrypt import Bcrypt
from Forms import *
from Faces import *
import modules.streaming
import modules.demography
from functools import wraps
import jwt
from cryptography.fernet import Fernet , InvalidToken
import html
from flask_mail import Mail, Message
import random
from hashlib import sha256
import qrcode
from twilio.rest import Client
import pyotp
from wtforms.fields.simple import HiddenField
import requests
import logging
import time
logging.basicConfig(level=logging.DEBUG)


bcrypt = Bcrypt()
app = Flask(__name__)
app.secret_key = 'your secret key'
app.config['UPLOAD_FOLDER'] = 'static/faces'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeCbyIqAAAAAE783mAOOsyiJwmUHSX3aBPaeQBN'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeCbyIqAAAAAB3n0mQNKRv7CxQCVozt7T2S6ZfE'
mysql = MySQL(app)

# Twilio configuration
TWILIO_ACCOUNT_SID = 'ACb4f9bf3c0268c54d13157b5977370201'
TWILIO_AUTH_TOKEN = '28b6ec16cb4e84fa0de79bd1441d2eb8'
TWILIO_PHONE_NUMBER = '+15187597851'

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'shujie20010902@gmail.com'
app.config['MAIL_PASSWORD'] = 'hdpb zwyk vcvz yrbl'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

GOOGLE_CLIENT_ID = '548692514397-uos4mmjmgbjgjtjeejjiokvp9sd6gjhd.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
REDIRECT_URI = 'https://127.0.0.1:8443/login/callback'
AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/auth'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
USER_INFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'

mail = Mail(app)

with open('C:\key\private_key.pem', 'r') as f:
    private_key = f.read()

with open('C:\key\public_key.pem', 'r') as f:
    public_key = f.read()
def sanitize_input(input_string):
    # Remove any character that is not alphanumeric or a space
    sanitized_string = re.sub(r'[^a-zA-Z0-9 ]', '', input_string)
    return sanitized_string
def sanitize_password(input_string):
    # Remove any character that is not alphanumeric
    sanitized_string = re.sub(r'[^a-zA-Z0-9@$_.+!#%^&*(){}|,/?\-]', '', input_string)
    return sanitized_string

def sanitize_email(input_string):
    # Remove any character that is not alphanumeric
    sanitized_string = re.sub(r'[^a-zA-Z0-9@.+]', '', input_string)
    return sanitized_string

def sanitize_phone_number(input_string):
    # Remove any character that is not numbers and +
    sanitized_string = re.sub(r'[^0-9+]', '', input_string)
    return sanitized_string

def sanitize_otp(input_string):
    # Remove any character that is not numbers
    sanitized_string = re.sub(r'[^0-9]', '', input_string)
    return sanitized_string


def is_valid_password(password):
    # Check for valid password requirements
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+=-])[A-Za-z\d!@#$%^&*()_+=-]{8,20}$'
    match = re.match(pattern, password)
    return password if match else None

def is_valid_email(email):
    # Check for valid email requirements
    pattern = r'^[a-zA-Z0-9+]+@[a-zA-Z]+\.[com]{3}$'
    match = re.match(pattern, email)
    return email if match else None

def is_valid_phone_number(phone_number):
    # Check for valid phone number requirements
    pattern = r'^[+65]{3}\d{8}$'
    match = re.match(pattern, phone_number)
    return phone_number if match else None

def is_valid_otp(otp):
    # Check for valid OTP requirements
    pattern = r'^\d{6}$'
    match = re.match(pattern, otp)
    return otp if match else None


def encode_input(input_string):
    # HTML-encode special characters to prevent XSS attacks
    encoded_string = html.escape(input_string)
    return encoded_string

def validate_username(self, username):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id FROM accounts WHERE username = %s', (username.data,))
    existing_user = cursor.fetchone()
    cursor.close()
    if existing_user:
        raise ValidationError('\nThis username is already taken. Please choose a different one.')

def validate_email(self, email):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id FROM accounts WHERE email = %s', (email.data,))
    existing_email = cursor.fetchone()
    cursor.close()
    if existing_email:
        raise ValidationError('\nThis email is already registered. Please choose a different one.')

def validate_password(self, password):
    if password.data != self.reenter_password.data:
        raise ValidationError('\nPasswords must match.')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_type(file_path):
    file_signatures = {
        b'\xff\xd8\xff': 'image/jpeg',  # JPEG
        b'\x89PNG\r\n\x1a\n': 'image/png',  # PNG
        b'GIF87a': 'image/gif',  # GIF 87a
        b'GIF89a': 'image/gif',  # GIF 89a
    }
    with open(file_path, 'rb') as file:
        file_header = file.read(8)

    for signature, mime_type in file_signatures.items():
        if file_header.startswith(signature):
            return True
    return False

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, public_key, algorithms=["RS256"])
            # rm additional checks if needed, like verifying user existence in the database
        except jwt.ExpiredSignatureError:
            form = LoginForm()
            msg = 'Token expired!'
            return render_template('login.html', form=form, msg=msg)
        except jwt.InvalidTokenError:
            form = LoginForm()
            msg = 'Invalid token!'
            return render_template('login.html', form=form, msg=msg)

        return func(*args, **kwargs)

    return decorated
@app.route('/')
def home():
    return render_template('home.html')
def get_account_details_from_jwt(token):
    try:
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        return {
            'id': decoded['id'],
            'username': decoded['username'],
            'email': decoded['email'],
            'is_admin': decoded['is_admin'],
            # Add other necessary fields
        }
    except jwt.ExpiredSignatureError:
        return None  # Handle expired token
    except jwt.InvalidTokenError:
        return None  # Handle invalid token
@app.route('/admin_home')
def admin_home():
    if 'jwt' in request.cookies:
        try:
            user_data = jwt.decode(request.cookies['jwt'], public_key, algorithms=["RS256"])
            account = {
                'id': user_data['id'],
                'username': user_data['username'],
                'is_admin': user_data['role'],
                'totp_secret': user_data['totp_secret']
            }
            return render_template('admin_home.html', account=account)
        except jwt.ExpiredSignatureError:
            form = LoginForm()
            msg = 'Token expired!'
            return render_template('login.html', form=form, msg=msg)  # Handle expired token
        except jwt.InvalidTokenError:
            form = LoginForm()
            msg = 'Invalid token!'
            return render_template('login.html', form=form, msg=msg)  # Handle invalid token
    else:
        return redirect(url_for('login'))


@app.route('/super_admin')
def super_admin():
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch the logged-in user's account details
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        # Fetch all user accounts for the admin view, excluding the root account
        cursor.execute('SELECT id, username, email, is_admin, symmetric_key, admin_level_desc FROM accounts inner join adminlevel on is_admin = admin_level WHERE username != %s',
                       ('root',))
        accounts = cursor.fetchall()

        # Decrypt emails for each account
        for acc in accounts:
            encrypted_email = acc['email'].encode()
            if 'symmetric_key' in acc:
                key = acc['symmetric_key']
                key = base64.urlsafe_b64decode(key.encode('utf-8'))
                f = Fernet(key)
                acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
            else:
                acc['decrypted_email'] = "Key not available"

        action = f"{username} accessed the super admin page"
        background_color = "lightblue"
        log_action(action, background_color)

        return render_template('super_admin.html', account=account, accounts=accounts)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)


@app.route('/admin_level_1')
def admin_level_1():
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch the logged-in user's account details
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        # Fetch all user accounts for the admin view, excluding the root account
        cursor.execute('SELECT id, username, email, is_admin, symmetric_key, admin_level_desc FROM accounts inner join adminlevel on is_admin = admin_level WHERE username != %s',
                       ('root',))
        accounts = cursor.fetchall()

        # Decrypt emails for each account
        for acc in accounts:
            encrypted_email = acc['email'].encode()
            if 'symmetric_key' in acc:
                key = acc['symmetric_key']
                key = base64.urlsafe_b64decode(key.encode('utf-8'))
                f = Fernet(key)
                acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
            else:
                acc['decrypted_email'] = "Key not available"

        action = f"{username} accessed the admin level 1 page"
        background_color = "lightblue"
        log_action(action, background_color)

        return render_template('admin_level_1.html', account=account, accounts=accounts)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

@app.route('/admin_level_2')
def admin_level_2():
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch the logged-in user's account details
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        # Fetch all user accounts for the admin view, excluding the root account
        cursor.execute('SELECT id, username, email, is_admin, symmetric_key, admin_level_desc FROM accounts inner join adminlevel on is_admin = admin_level WHERE username != %s',
                       ('root',))
        accounts = cursor.fetchall()

        # Decrypt emails for each account
        for acc in accounts:
            encrypted_email = acc['email'].encode()
            if 'symmetric_key' in acc:
                key = acc['symmetric_key']
                key = base64.urlsafe_b64decode(key.encode('utf-8'))
                f = Fernet(key)
                acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
            else:
                acc['decrypted_email'] = "Key not available"

        action = f"{username} accessed the admin level 2 page"
        background_color = "lightblue"
        log_action(action, background_color)

        return render_template('admin_level_2.html', account=account, accounts=accounts)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)
@app.route('/admin_level_3')
def admin_level_3():
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch the logged-in user's account details
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        # Fetch all user accounts for the admin view, excluding the root account
        cursor.execute('SELECT id, username, email, is_admin, symmetric_key, admin_level_desc FROM accounts inner join adminlevel on is_admin = admin_level WHERE username != %s',
                       ('root',))
        accounts = cursor.fetchall()

        # Decrypt emails for each account
        for acc in accounts:
            encrypted_email = acc['email'].encode()
            if 'symmetric_key' in acc:
                key = acc['symmetric_key']
                key = base64.urlsafe_b64decode(key.encode('utf-8'))
                f = Fernet(key)
                acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
            else:
                acc['decrypted_email'] = "Key not available"

        action = f"{username} accessed the admin level 3 page"
        background_color = "lightblue"
        log_action(action, background_color)

        return render_template('admin_level_3.html', account=account, accounts=accounts)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)
@app.route('/admin_level_4')
def admin_level_4():
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch the logged-in user's account details
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        # Fetch all user accounts for the admin view, excluding the root account
        cursor.execute('SELECT id, username, email, is_admin, symmetric_key, admin_level_desc FROM accounts inner join adminlevel on is_admin = admin_level WHERE username != %s',
                       ('root',))
        accounts = cursor.fetchall()

        # Decrypt emails for each account
        for acc in accounts:
            encrypted_email = acc['email'].encode()
            if 'symmetric_key' in acc:
                key = acc['symmetric_key']
                key = base64.urlsafe_b64decode(key.encode('utf-8'))
                f = Fernet(key)
                acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
            else:
                acc['decrypted_email'] = "Key not available"

        action = f"{username} accessed the admin level 4 page"
        background_color = "lightblue"
        log_action(action, background_color)

        return render_template('admin_level_4.html', account=account, accounts=accounts)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

@app.route('/public')
def public():
    return 'Anyone can access this'

@app.route('/private')
@token_required
def auth():
    return 'JWT is verified. Welcome to your private page!'

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

#OAUTH START
class OAuthRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    reenter_password = PasswordField('Re-enter Password', validators=[DataRequired()])
    email = HiddenField('Email')  # Hidden field because it's pre-filled and not editable
    phone_number = HiddenField('Phone Number')  # Hidden field because it's pre-filled and not editable
    submit = SubmitField('Register')

    def validate_username(self, username):
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id FROM accounts WHERE username = %s', (username.data,))
        existing_user = cursor.fetchone()
        cursor.close()
        if existing_user:
            raise ValidationError('\nThis username is already taken. Please choose a different one.')

    def validate_email(self, email):
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id FROM accounts WHERE email = %s', (email.data,))
        existing_email = cursor.fetchone()
        cursor.close()
        if existing_email:
            raise ValidationError('\nThis email is already registered. Please choose a different one.')

    def validate_password(self, password):
        if password.data != self.reenter_password.data:
            raise ValidationError('\nPasswords must match.')


@app.route('/login/google')
def google_login():
    base_url = "https://accounts.google.com/o/oauth2/auth"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": REDIRECT_URI,
        "state": "random_state_string"  # You should generate a random state string
    }
    # Manually construct the authorization URL
    authorization_url = f"{base_url}?{urlencode(params)}"

    # Save the state in the session for later validation
    session['oauth_state'] = params['state']

    return redirect(authorization_url)


@app.route('/login/callback')
def callback():
    try:
        # Step 1: Extract the authorization code from the callback URL
        code = request.args.get('code')
        if not code:
            return "Authorization code not found", 400

        # Step 2: Exchange the authorization code for an access token
        token_data = {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': REDIRECT_URI,
            'grant_type': 'authorization_code'
        }

        token_response = requests.post(TOKEN_URL, data=token_data)
        token_response_data = token_response.json()

        if token_response.status_code != 200:
            return f"Token request failed: {token_response_data.get('error_description')}", 400

        access_token = token_response_data['access_token']

        # Step 3: Use the access token to get user info from Google
        user_info_response = requests.get(USER_INFO_URL, headers={'Authorization': f'Bearer {access_token}'})
        user_info = user_info_response.json()

        if user_info_response.status_code != 200:
            return f"Failed to retrieve user info: {user_info.get('error_description')}", 400

        # Step 4: Handle the user information (e.g., log them in or register them)
        email = user_info['email'].strip().lower()

        logging.debug(f"Checking database for email: {email}")

        # Make cursor return results as a dictionary
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT id, username, email, phone_number, totp_secret, is_admin, symmetric_key, email_notifications FROM accounts')
        accounts = cursor.fetchall()

        account = None
        for acc in accounts:
            try:
                key = base64.urlsafe_b64decode(acc['symmetric_key'])
                f = Fernet(key)
                decrypted_email = f.decrypt(acc['email'].encode()).decode()

                if decrypted_email.strip().lower() == email:
                    account = acc
                    break
            except InvalidToken:
                logging.error(f"Failed to decrypt email for account ID {acc['id']}")
                continue

        logging.debug(f"Account fetched from database: {account}")

        if account:
            # User exists, set the user_data cookie as in the login function
            logging.debug("User exists. Proceeding to 2FA.")
            if account['email_notifications'] == 1:
                encrypted_email = account['email'].encode()
                key = base64.urlsafe_b64decode(account['symmetric_key'].encode('utf-8'))
                f = Fernet(key)
                decrypted_email = f.decrypt(encrypted_email).decode('utf-8')
                # Create the email subject and body
                subject = 'Important: Login Notification'
                body = (f"Dear {account['username']},\n\n"
                        f"We wanted to let you know that your account was accessed on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}.\n\n"
                        f"If you did not initiate this login, please take the following actions immediately:\n"
                        f"- Change your password.\n"
                        f"- Review your recent account activity.\n"
                        f"- Contact our support team if you have any concerns.\n\n"
                        f"If this was you, there's no need to take further action.\n\n"
                        f"Thank you for your attention to this matter.\n\n"
                        f"Best regards,\n"
                        f"The [Laundromat] Team\n\n"
                        f"Contact Us:\n"
                        f"Email: support@example.com\n"
                        f"Phone: +123-456-7890\n"
                        f"Website: www.example.com\n\n"
                        f"---\n"
                        f"This is an automated notification. Please do not reply to this email.")

                # Create and send the email
                msg = Message(subject, sender='noreply@example.com', recipients=[decrypted_email])
                msg.body = body
                mail.send(msg)
            user_data = jwt.encode({
                'id': account['id'],
                'username': account['username'],
                'role': account['is_admin'],
                'totp_secret': account['totp_secret'],
                'otp_sent_at': datetime.utcnow().isoformat()
            }, private_key, algorithm='RS256')
            action = f"{account['username']} login through Google OAuth"
            background_color = "lightgreen"
            log_action1(account['id'], action, background_color)
            resp = make_response(redirect(url_for('choice')))
            resp.set_cookie('user_data', user_data, httponly=True, secure=True, max_age=10 * 60)  # 10 minutes
            return resp
        else:
            # User doesn't exist, redirect to OAuth registration with plain email
            logging.debug("User does not exist. Redirecting to registration.")
            return redirect(url_for('oauth_register', email=email, phone_number='+6591722593'))

    except Exception as e:
        logging.error(f"Exception in callback: {str(e)}")
        abort(500)

@app.route('/oauth_register', methods=['GET', 'POST'])
def oauth_register():
    # Retrieve the email and phone number from the URL parameters
    email = request.args.get('email')
    phone_number = request.args.get('phone_number', '+6591722593')

    # Initialize the form with pre-filled email and phone number
    form = OAuthRegistrationForm(email=email, phone_number=phone_number)

    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        email = form.email.data  # Already encrypted when passed
        phone_number = form.phone_number.data

        # Sanitize and encode inputs
        username = sanitize_input(username)
        email = sanitize_email(email)
        password = sanitize_password(password)
        phone_number = sanitize_phone_number(phone_number)

        password = is_valid_password(password)
        email = is_valid_email(email)
        phone_number = is_valid_phone_number(phone_number)
        if password is None:
            form = LoginForm()
            msg='Please enter a valid password.'
            return render_template('login.html',form=form,msg=msg)
        elif email is None:
            form = LoginForm()
            msg='Please enter a valid email address.'
            return render_template('login.html',form=form,msg=msg)
        elif phone_number is None:
            form = LoginForm()
            msg='Please enter a valid phone number.'
            return render_template('login.html',form=form,msg=msg)
        else:
            pass
        username = encode_input(username)
        password = encode_input(password)
        email = encode_input(email)
        phone_number = encode_input(phone_number)

        # Encrypt the email again before saving to the database (if needed)
        key = Fernet.generate_key()
        f = Fernet(key)
        email_bytes = email.encode()
        encrypted_email = f.encrypt(email_bytes).decode()

        # Hash the password using Flask-Bcrypt's generate_password_hash method
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Generate a TOTP secret
        totp_secret = pyotp.random_base32()
        password_create = datetime.now()
        password_expiry_days = 90  # Default or fetched from your schema
        password_expiry = password_create + timedelta(days=password_expiry_days)
        # Insert the new user into the database
        cursor = mysql.connection.cursor()
        cursor.execute(
            'INSERT INTO accounts (username, password, email, phone_number, totp_secret, is_admin, symmetric_key, password_expiry_days, password_expiry) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
            (username, hashed_password, encrypted_email, phone_number, totp_secret, 1, base64.urlsafe_b64encode(key).decode('utf-8'), password_expiry_days, password_expiry)
        )
        mysql.connection.commit()
        cursor.close()

        flash('Registration successful. Please log in.', 'success')

        # Redirect to the login page after successful registration
        return redirect(url_for('login'))

    return render_template('oauth_register.html', form=form)

#OAUTH

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password1 = form.password1.data
        password2 = form.password2.data
        phone_number = form.phone_number.data

        # Sanitize input
        username = sanitize_input(username)
        email = sanitize_email(email)
        password1 = sanitize_password(password1)
        password2 = sanitize_password(password2)
        phone_number = sanitize_phone_number(phone_number)

        # Validate input
        email = is_valid_email(email)
        password1 = is_valid_password(password1)
        password2 = is_valid_password(password2)
        phone_number = is_valid_phone_number(phone_number)
        if password1 is None:
            msg = "Please enter a valid password."
            return render_template('register.html', form=form, msg=msg)
        elif password2 is None:
            msg = "Please enter a valid password."
            return render_template('register.html', form=form, msg=msg)
        elif email is None:
            msg = "Please enter a valid email address."
            return render_template('register.html', form=form, msg=msg)
        elif phone_number is None:
            msg = "Please enter a valid phone number."
            return render_template('register.html', form=form, msg=msg)
        else:
            # Encode input
            username = encode_input(username)
            email = encode_input(email)
            password1 = encode_input(password1)
            password2 = encode_input(password2)
            phone_number = encode_input(phone_number)

            if password1 != password2:
                msg = 'Passwords do not match. Please try again.'
                return render_template('register.html', form=form, msg=msg)
            # Check if username or email already exists in accounts table
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (username, email))
            existing_user = cursor.fetchone()

            if existing_user:
                msg = 'Username or Email already exists. Please choose another.'
                cursor.close()
                return render_template('register.html', form=form, msg=msg)

            # Encrypt email
            key = Fernet.generate_key()
            encoded_key = base64.urlsafe_b64encode(key).decode('utf-8')
            f = Fernet(key)
            email_bytes = email.encode()
            encrypted_email = f.encrypt(email_bytes).decode()  # Convert to string

            # Hash password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password2).decode('utf-8')

            # Generate OTP
            otp = generate_otp()
            # Generate TOTP secret
            totp_secret = pyotp.random_base32()

            # Create a temporary JWT
            token = jwt.encode({
                'username': username,
                'password': hashed_password,
                'email': encrypted_email,
                'phone_number': phone_number,
                'otp': otp,
                'totp_secret': totp_secret,
                'symmetric_key': encoded_key,
                'otp_sent_at': datetime.utcnow().isoformat()
            }, private_key, algorithm='RS256')

            # Send OTP to email
            msg = Message('Confirm your email', sender='your_email@example.com', recipients=[email])
            msg.body = f'Your OTP is {otp}'
            mail.send(msg)
            flash('An OTP has been sent to your email. Please verify.', 'info')

            # Set the JWT in a cookie
            resp = make_response(redirect(url_for('verify_email')))
            resp.set_cookie('registration_token', token, httponly=True, secure=True, max_age=10 * 60)  # 10 minutes
            return resp

    return render_template('register.html', form=form)


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    form = OTPForm()
    token = request.cookies.get('registration_token')
    if token:
        try:
            data = jwt.decode(token, public_key, algorithms=["RS256"])
            if form.validate_on_submit():
                otp = form.otp.data
                otp = sanitize_otp(otp)
                otp = is_valid_otp(otp)
                if otp is None:
                    msg = 'Incorrect OTP'
                    return render_template('verify_email.html', form=form, msg=msg)
                otp = encode_input(otp)
                if otp == data['otp']:
                    # Calculate the password expiry date
                    password_create = datetime.now()  # Assume the current datetime as password_create
                    password_expiry_days = 90  # Default or fetched from your schema
                    password_expiry = password_create + timedelta(days=password_expiry_days)

                    # Insert data into the accounts table, including password_expiry
                    cursor = mysql.connection.cursor()
                    cursor.execute('''
                                            INSERT INTO accounts (username, password, email, phone_number, totp_secret, symmetric_key, password_expiry_days, password_expiry)
                                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                        ''', (
                    data['username'], data['password'], data['email'], data['phone_number'], data['totp_secret'],
                    data['symmetric_key'], password_expiry_days, password_expiry))
                    mysql.connection.commit()
                    cursor.close()

                    cursor = mysql.connection.cursor()
                    cursor.execute('SELECT id FROM accounts where username = %s', (data['username'],))
                    new_user = cursor.fetchone()
                    cursor.close()
                    id = new_user[0]
                    action = f"{data['username']} registered email"
                    background_color = "lightgreen"
                    log_action1(id, action, background_color)

                    # Clear the registration token cookie
                    resp = make_response(redirect(url_for('login')))
                    resp.delete_cookie('registration_token')
                    return resp
                else:
                    msg = 'Incorrect OTP'
                    return render_template('verify_email.html', form=form, msg=msg)
            return render_template('verify_email.html', form=form)
        except jwt.ExpiredSignatureError:
            form = LoginForm()
            msg = 'Token expired!'
            return render_template('login.html', form=form, msg=msg)
        except jwt.InvalidTokenError:
            form = LoginForm()
            msg = 'Invalid token!'
            return render_template('login.html', form=form, msg=msg)
    else:
        form = RegistrationForm()
        msg = 'No registration token found.'
        return render_template('register.html', form=form, msg=msg)

@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if request.method=='POST':
        if form.validate_on_submit():
            username=form.username.data
            password=form.password.data
            username=sanitize_input(username)
            password=sanitize_password(password)

            password=is_valid_password(password)
            if password is None:
                msg='Please enter a valid password.'
                return render_template('login.html',form=form,msg=msg)

            username=encode_input(username)
            password=encode_input(password)

            cursor=mysql.connection.cursor()
            try:
                cursor.execute(
                    "SELECT id, phone_number, email, symmetric_key, email_notifications, password, is_admin, totp_secret FROM accounts WHERE username = %s",
                    (username,))
                user=cursor.fetchone()

                if user:
                    # Unpack the tuple returned by cursor.fetchone()
                    id,phone_number,email,symmetric_key,email_notifications,password_hash,is_admin,totp_secret=user

                    if bcrypt.check_password_hash(password_hash,password):
                        # Decrypt email
                        encrypted_email=email.encode()
                        key=base64.urlsafe_b64decode(symmetric_key.encode('utf-8'))
                        f=Fernet(key)
                        decrypted_email=f.decrypt(encrypted_email).decode('utf-8')

                        # Send email if notifications are enabled
                        if email_notifications:
                            # Create the email subject and body
                            subject='Important: Login Notification'
                            body=(f"Dear {username},\n\n"
                                  f"We wanted to let you know that your account was accessed on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}.\n\n"
                                  f"If you did not initiate this login, please take the following actions immediately:\n"
                                  f"- Change your password.\n"
                                  f"- Review your recent account activity.\n"
                                  f"- Contact our support team if you have any concerns.\n\n"
                                  f"If this was you, there's no need to take further action.\n\n"
                                  f"Thank you for your attention to this matter.\n\n"
                                  f"Best regards,\n"
                                  f"The [Laundromat] Team\n\n"
                                  f"Contact Us:\n"
                                  f"Email: support@example.com\n"
                                  f"Phone: +123-456-7890\n"
                                  f"Website: www.example.com\n\n"
                                  f"---\n"
                                  f"This is an automated notification. Please do not reply to this email.")

                            # Create and send the email
                            msg=Message(subject,sender='noreply@example.com',recipients=[decrypted_email])
                            msg.body=body
                            mail.send(msg)

                        action=f"{username} login through username and password"
                        background_color="lightgreen"
                        log_action1(id,action,background_color)

                        user_data=jwt.encode({'id': id,'username': username,'role': is_admin,'totp_secret': totp_secret,
                            'otp_sent_at': datetime.utcnow().isoformat()},private_key,algorithm='RS256')

                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        # Query to find users whose passwords are either expired or about to expire
                        cursor.execute('''
                                            SELECT id, username, email, symmetric_key, password_expiry
                                            FROM accounts 
                                            WHERE password_expiry <= NOW() + INTERVAL 1 DAY
                                        ''')
                        users = cursor.fetchall()
                        cursor.close()
                        # token = request.cookies.get('user_data')
                        for user in users:
                            if user['password_expiry'] <= datetime.now():
                                # Account already expired
                                url = forgot_password().strip()
                                url = url.replace('\n', '')
                                return url
                            else:
                                pass
                        resp=make_response(redirect(url_for('choice')))
                        resp.set_cookie('user_data',user_data,httponly=True,secure=True,max_age=10 * 60)  # 10 minutes
                        return resp
                    else:
                        msg='Incorrect username or password.'
                        return render_template('login.html',form=form,msg=msg)
                else:
                    msg='Username not found.'
                    return render_template('login.html',form=form,msg=msg)
            finally:
                cursor.close()
        else:
            msg = 'Form validation failed.'
            form = LoginForm()
            return render_template('login.html', form=form, msg=msg)
    return render_template('login.html',form=form)


@app.route('/choice', methods=['GET', 'POST'])
def choice():
    form = ChoiceForm()
    if form.validate_on_submit():
        selected_medium = form.medium.data
        token = request.cookies.get('user_data')
        if token:
            try:
                data = jwt.decode(token, public_key, algorithms=["RS256"])
                data['selected_medium'] = selected_medium
                new_token = jwt.encode(data, private_key, algorithm='RS256')
                resp = make_response(redirect(url_for(f'send_otp_{selected_medium}')))
                resp.set_cookie('user_data', new_token, httponly=True, secure=True, max_age=10 * 60)  # 10 minutes
                return resp
            except jwt.ExpiredSignatureError:
                form = LoginForm()
                msg = 'Token expired!'
                return render_template('login.html', form=form, msg=msg)
            except jwt.InvalidTokenError:
                form = LoginForm()
                msg = 'Invalid token!'
                return render_template('login.html', form=form, msg=msg)
        else:
            form = LoginForm()
            msg = 'Token is missing!'
            return render_template('login.html', form=form, msg=msg)
    return render_template('choice.html', form=form)


@app.route('/permission', methods=['GET', 'POST'])
def permission():
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        role = data['role']

        if role == 1:
            return redirect(url_for('home'))
        elif role == 2:
            return redirect(url_for('admin_home'))
        elif role == 3:
            return redirect(url_for('admin_home'))
        elif role == 4:
            return redirect(url_for('admin_home'))
        elif role == 5:
            return redirect(url_for('admin_home'))
        elif role == 6:
            return redirect(url_for('admin_home'))
        else:
            form = LoginForm()
            msg = 'You do not have permission to access this page.'
            return render_template('login.html', form=form, msg=msg)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

@app.route('/view_user/<int:user_id>')
def view_user(user_id):
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts inner join adminlevel on is_admin = admin_level WHERE id = %s', (user_id,))
        account = cursor.fetchone()

        if account:
            encrypted_email = account['email'].encode()
            key = account['symmetric_key']
            key = base64.urlsafe_b64decode(key.encode('utf-8'))
            f = Fernet(key)
            decrypted_email = f.decrypt(encrypted_email).decode('utf-8')
            account['decrypted_email'] = decrypted_email

            action = f"{data['username']} viewed user {account['username']}"
            background_color = "lightgreen"
            log_action(action, background_color)
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT action, timestamp, background_color FROM logging where user_id = %s", (user_id,))
            logs = cursor.fetchall()
            cursor.close()
            return render_template('view_user.html', account=account, logs=logs)
        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            # Fetch the logged-in user's account details
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            # Fetch all user accounts for the admin view, excluding the root account
            cursor.execute('SELECT id, username, email, is_admin, symmetric_key FROM accounts WHERE username != %s',
                           ('root',))
            accounts = cursor.fetchall()

            # Decrypt emails for each account
            for acc in accounts:
                encrypted_email = acc['email'].encode()
                if 'symmetric_key' in acc:
                    key = acc['symmetric_key']
                    key = base64.urlsafe_b64decode(key.encode('utf-8'))
                    f = Fernet(key)
                    acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
                else:
                    acc['decrypted_email'] = "Key not available"
            msg = 'User not found!'
            return render_template('admin_home.html', msg=msg, accounts=accounts, account=account)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

# Edit User
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    token = request.cookies.get('jwt')
    form = EditUserForm()

    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
        account = cursor.fetchone()

        if request.method == 'POST' and form.validate_on_submit():
            new_username = form.username.data
            new_username = sanitize_input(new_username)
            new_username = encode_input(new_username)
            cursor.execute('UPDATE accounts SET username = %s WHERE id = %s', (new_username, user_id))
            mysql.connection.commit()
            cursor.close()
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            # Fetch the logged-in user's account details
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            # Fetch all user accounts for the admin view, excluding the root account
            cursor.execute('SELECT id, username, email, is_admin, symmetric_key FROM accounts WHERE username != %s',
                           ('root',))
            accounts = cursor.fetchall()

            # Decrypt emails for each account
            for acc in accounts:
                encrypted_email = acc['email'].encode()
                if 'symmetric_key' in acc:
                    key = acc['symmetric_key']
                    key = base64.urlsafe_b64decode(key.encode('utf-8'))
                    f = Fernet(key)
                    acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
                else:
                    acc['decrypted_email'] = "Key not available"
            msg = 'Username updated successfully!'
            return render_template('admin_home.html',account=account,accounts=accounts, msg=msg)

        return render_template('edit_user.html', account=account, form=form)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)


# Change Password
@app.route('/change_password/<int:user_id>', methods=['GET', 'POST'])
def change_password(user_id):
    token = request.cookies.get('jwt')
    form = ChangePasswordForm()
    try:
        # Decode the JWT token
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']

        # Initialize cursor
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
        account = cursor.fetchone()
        if request.method == 'POST' and form.validate_on_submit():
            new_password = form.new_password.data
            confirm_password = form.confirm_password.data
            new_password = sanitize_password(new_password)
            confirm_password = sanitize_password(confirm_password)
            new_password = is_valid_password(new_password)
            confirm_password = is_valid_password(confirm_password)
            if new_password is None:
                msg = 'Invalid password!'
                return render_template('change_password.html', account=account, msg=msg)
            elif confirm_password is None:
                msg = 'Invalid confirm password!'
                return render_template('change_password.html', account=account, msg=msg)
            else:
                new_password = encode_input(new_password)
                confirm_password = encode_input(confirm_password)

                # Hash the new password before storing it
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                cursor.execute('UPDATE accounts SET password = %s WHERE username = %s', (hashed_password, username))
                mysql.connection.commit()
                cursor.close()

                password_expiry_days = 90
                password_expiry = datetime.now() + timedelta(days=password_expiry_days)
                cursor = mysql.connection.cursor()
                cursor.execute("UPDATE accounts SET password_expiry = %s WHERE username = %s",
                               (password_expiry, username))
                mysql.connection.commit()
                cursor.close()

                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

                # Fetch the logged-in user's account details
                cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
                account = cursor.fetchone()

                # Fetch all user accounts for the admin view, excluding the root account
                cursor.execute('SELECT id, username, email, is_admin, symmetric_key FROM accounts WHERE username != %s',
                               ('root',))
                accounts = cursor.fetchall()

                # Decrypt emails for each account
                for acc in accounts:
                    encrypted_email = acc['email'].encode()
                    if 'symmetric_key' in acc:
                        key = acc['symmetric_key']
                        key = base64.urlsafe_b64decode(key.encode('utf-8'))
                        f = Fernet(key)
                        acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
                    else:
                        acc['decrypted_email'] = "Key not available"
                msg = 'Password changed successfully!'
                return render_template('admin_home.html',account=account,accounts=accounts, msg=msg)

        return render_template('change_password.html', account=account, form=form)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

#delete user
@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
        account = cursor.fetchone()

        if request.method == 'POST':
            # Delete related records first
            cursor.execute('DELETE FROM logging WHERE user_id = %s', (user_id,))  # Adjust table name as needed
            # Now delete the user
            cursor.execute('DELETE FROM accounts WHERE id = %s', (user_id,))
            mysql.connection.commit()
            cursor.close()
            face = account['image_pathLocation']
            if face is not None:
                os.remove(face)
            msg = f'{account["username"]} deleted successfully!'
            background_color = "lightgreen"
            log_action(msg, background_color)
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            # Fetch the logged-in user's account details
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            # Fetch all user accounts for the admin view, excluding the root account
            cursor.execute('SELECT id, username, email, is_admin, symmetric_key FROM accounts WHERE username != %s',
                           ('root',))
            accounts = cursor.fetchall()

            # Decrypt emails for each account
            for acc in accounts:
                encrypted_email = acc['email'].encode()
                if 'symmetric_key' in acc:
                    key = acc['symmetric_key']
                    key = base64.urlsafe_b64decode(key.encode('utf-8'))
                    f = Fernet(key)
                    acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
                else:
                    acc['decrypted_email'] = "Key not available"
            msg = 'User deleted successfully!'
            return render_template('admin_home.html',account=account,accounts=accounts, msg=msg)

        return render_template('delete_user.html', account=account)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

# Update Admin Level
@app.route('/update_admin_level/<int:user_id>', methods=['GET', 'POST'])
def update_admin_level(user_id):
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Get current account info
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
        account = cursor.fetchone()

        if request.method == 'POST':
            new_level = request.form['admin_level']
            # Update the admin level in the database
            cursor.execute('UPDATE accounts SET is_admin = %s WHERE id = %s', (new_level, user_id))
            mysql.connection.commit()
            cursor.close()
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            # Fetch the logged-in user's account details
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            # Fetch all user accounts for the admin view, excluding the root account
            cursor.execute('SELECT id, username, email, is_admin, symmetric_key FROM accounts WHERE username != %s',
                           ('root',))
            accounts = cursor.fetchall()

            # Decrypt emails for each account
            for acc in accounts:
                encrypted_email = acc['email'].encode()
                if 'symmetric_key' in acc:
                    key = acc['symmetric_key']
                    key = base64.urlsafe_b64decode(key.encode('utf-8'))
                    f = Fernet(key)
                    acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
                else:
                    acc['decrypted_email'] = "Key not available"
            msg = 'Admin level updated successfully!'
            return render_template('admin_home.html',account=account,accounts=accounts, msg=msg)

        return render_template('update_admin_level.html', account=account)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)



@app.route('/send_otp_email', methods=['GET'])
def send_otp_email():
    token = request.cookies.get('user_data')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)

    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        totp_secret = data['totp_secret']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT email, symmetric_key FROM accounts WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            email = user[0]
            key = user[1]
            totp = pyotp.TOTP(totp_secret)
            key = base64.urlsafe_b64decode(key.encode('utf-8'))
            f = Fernet(key)
            email = f.decrypt(email.encode()).decode()

            verification_code = totp.now()
            data['otp'] = verification_code
            new_token = jwt.encode(data, private_key, algorithm='RS256')
            resp = make_response(redirect(url_for('verify_login_email_otp')))
            resp.set_cookie('user_data', new_token, httponly=True, secure=True, max_age=10 * 60)  # 10 minutes

            msg = Message('Confirm your email', sender='your_email@example.com', recipients=[email])
            msg.body = f'Your OTP is {verification_code}'
            mail.send(msg)

            return resp
        else:
            form = LoginForm()
            msg = 'User not found.'
            return render_template('login.html',form=form, msg=msg)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')
        traceback.print_exc()


@app.route('/verify_login_email_otp', methods=['GET', 'POST'])
def verify_login_email_otp():
    form = OTPForm()
    if request.method == 'POST' and form.validate_on_submit():
        otp = form.otp.data

        otp = sanitize_otp(otp)
        otp = is_valid_otp(otp)
        if otp is None:
            msg = 'Incorrect OTP'
            return render_template('verify_login_email_otp.html', form=form, msg=msg)
        otp = encode_input(otp)

        token = request.cookies.get('user_data')

        if not token:
            form = LoginForm()
            msg = 'Token is missing!'
            return render_template('login.html', form=form, msg=msg)

        try:
            data = jwt.decode(token, public_key, algorithms=["RS256"])
            otp_from_token = data.get('otp')
            username = data.get('username')
            id = data.get('id')
            if otp == otp_from_token:
                data['is_verified'] = True
                action = f"{username} login successfully through email OTP"
                background_color = "lightgreen"
                log_action1(id, action, background_color)
                new_token = jwt.encode(data, private_key, algorithm='RS256')
                resp = make_response(redirect(url_for('permission')))
                resp.set_cookie('jwt', new_token, httponly=True, secure=True, max_age=30 * 60)
                resp.delete_cookie('user_data')
                return resp
            else:
                action = f"{username} inputted wrong email OTP"
                background_color = "crimson"
                log_action1(id, action, background_color)
                msg = 'Incorrect OTP'
                return render_template('verify_login_email_otp.html', form=form, msg=msg)

        except jwt.ExpiredSignatureError:
            form = LoginForm()
            msg = 'Token expired!'
            return render_template('login.html', form=form, msg=msg)
        except jwt.InvalidTokenError:
            form = LoginForm()
            msg = 'Invalid token!'
            return render_template('login.html', form=form, msg=msg)

    return render_template('verify_login_email_otp.html', form=form)


@app.route('/send_otp_phone',methods=['GET'])
def send_otp_phone():
    token=request.cookies.get('user_data')
    if not token:
        form=LoginForm()
        msg='Token is missing!'
        return render_template('login.html',form=form,msg=msg)

    try:
        data=jwt.decode(token,public_key,algorithms=["RS256"])
        username=data['username']
        totp_secret=data['totp_secret']

        cursor=mysql.connection.cursor()
        cursor.execute("SELECT phone_number FROM accounts WHERE username = %s",(username,))
        user=cursor.fetchone()
        cursor.close()

        if user:
            phone_number=user[0]
            totp=pyotp.TOTP(totp_secret)

            verification_code=totp.now()
            client.messages.create(body=f"Your verification code is {verification_code}",from_=TWILIO_PHONE_NUMBER,
                                   to=phone_number)

            # Set OTP and its expiration time (20 seconds from now)
            data['otp']=verification_code
            data['otp_expiration']=time.time() + 20  # OTP valid for 20 seconds

            new_token=jwt.encode(data,private_key,algorithm='RS256')
            resp=make_response(redirect(url_for('verify_phone')))
            resp.set_cookie('user_data',new_token,httponly=True,secure=True,max_age=10 * 60)
            flash('Verification code sent to phone!','info')

            return resp
        else:
            form=LoginForm()
            msg='User not found.'
            return render_template('login.html',form=form,msg=msg)
    except jwt.ExpiredSignatureError:
        form=LoginForm()
        msg='Token expired!'
        return render_template('login.html',form=form,msg=msg)
    except jwt.InvalidTokenError:
        form=LoginForm()
        msg='Invalid token!'
        return render_template('login.html',form=form,msg=msg)

@app.route('/verify_phone', methods=['GET', 'POST'])
def verify_phone():
    form = VerificationForm()
    otp_expired = False

    if request.method == 'POST' and form.validate_on_submit():
        otp = form.verification_code.data

        otp = sanitize_otp(otp)
        otp = is_valid_otp(otp)
        if otp is None:
            msg = 'Incorrect OTP'
            return render_template('verify_phone.html', form=form, msg=msg, otp_expired=otp_expired)

        otp = encode_input(otp)
        token = request.cookies.get('user_data')

        if not token:
            form = LoginForm()
            msg = 'Token is missing!'
            return render_template('login.html', form=form, msg=msg)

        try:
            data = jwt.decode(token, public_key, algorithms=["RS256"])
            otp_from_token = data.get('otp')
            otp_expiration = data.get('otp_expiration')
            username = data.get('username')
            id = data.get('id')

            if time.time() > otp_expiration:
                otp_expired = True
                msg = 'OTP expired! Please resend the OTP.'
                return render_template('verify_phone.html', form=form, msg=msg, otp_expired=otp_expired)

            if otp == otp_from_token:
                data['is_verified'] = True
                action = f"{username} login successfully through phone OTP"
                background_color = "lightgreen"
                log_action1(id, action, background_color)
                new_token = jwt.encode(data, private_key, algorithm='RS256')
                resp = make_response(redirect(url_for('permission')))
                resp.set_cookie('jwt', new_token, httponly=True, secure=True, max_age=30 * 60)
                resp.delete_cookie('user_data')
                return resp
            else:
                action = f"{username} inputted wrong phone OTP"
                background_color = "crimson"
                log_action1(id, action, background_color)
                msg = 'Incorrect OTP'
                return render_template('verify_phone.html', form=form, msg=msg, otp_expired=otp_expired)

        except jwt.ExpiredSignatureError:
            form = LoginForm()
            msg = 'Token expired!'
            return render_template('login.html', form=form, msg=msg)
        except jwt.InvalidTokenError:
            form = LoginForm()
            msg = 'Invalid token!'
            return render_template('login.html', form=form, msg=msg)

    return render_template('verify_phone.html', form=form, otp_expired=otp_expired)

@app.route('/send_otp_google_auth', methods=['GET'])
def send_otp_google_auth():
    token = request.cookies.get('user_data')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)

    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        user_id = data['id']
        totp_secret = data['totp_secret']

        # Check the database for a successful Google Authenticator login
        cursor = mysql.connection.cursor()
        query = "SELECT COUNT(*) FROM logging WHERE action = %s AND user_id = %s"
        cursor.execute(query, ("{} login successfully through Google Authenticator".format(username), user_id))
        result = cursor.fetchone()
        cursor.close()

        form = VerificationForm()  # Ensure that form is instantiated here

        if result[0] > 0:
            # User has successfully logged in with Google Authenticator before, so skip QR code but still ask for OTP
            return render_template('verify_google_auth.html', form=form, qr_code_url=None)

        # Generate the QR Code URL
        totp = pyotp.TOTP(totp_secret)
        qr_code_url = totp.provisioning_uri(name=username, issuer_name='YourAppName')

        # Generate the QR Code image
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(qr_code_url)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        img.save('static/img/qr_code.png')  # Save the QR code image to the static folder

        return render_template('verify_google_auth.html', form=form, qr_code_url=url_for('static', filename='img/qr_code.png'))

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)



@app.route('/verify_google_auth', methods=['GET', 'POST'])
def verify_google_auth():
    form = VerificationForm()
    qr_code_url = request.form.get('qr_code_url')  # Get the QR code URL from the hidden field

    if request.method == 'POST' and form.validate_on_submit():
        otp = form.verification_code.data

        otp = sanitize_otp(otp)
        otp = is_valid_otp(otp)
        if otp is None:
            msg = 'Incorrect OTP'
            return render_template('verify_google_auth.html', form=form, msg=msg, qr_code_url=qr_code_url)

        otp = encode_input(otp)
        token = request.cookies.get('user_data')

        if not token:
            form = LoginForm()
            msg = 'Token is missing!'
            return render_template('login.html', form=form, msg=msg)

        try:
            data = jwt.decode(token, public_key, algorithms=["RS256"])
            totp_secret = data.get('totp_secret')
            username = data.get('username')
            id = data.get('id')

            if totp_secret:
                # Verify OTP for Google Authenticator
                totp = pyotp.TOTP(totp_secret)
                if totp.verify(otp):
                    data['is_verified'] = True
                    action = f"{username} login successfully through Google Authenticator"
                    background_color = "lightgreen"
                    log_action1(id, action, background_color)
                    new_token = jwt.encode(data, private_key, algorithm='RS256')
                    resp = make_response(redirect(url_for('permission')))
                    resp.set_cookie('jwt', new_token, httponly=True, secure=True, max_age=30 * 60)
                    resp.delete_cookie('user_data')
                    return resp
                else:
                    action = f"{username} inputted wrong Google Authenticator OTP"
                    background_color = "crimson"
                    log_action1(id, action, background_color)
                    msg = 'Incorrect OTP'
                    return render_template('verify_google_auth.html', form=form, msg=msg, qr_code_url=qr_code_url)
            else:
                form = LoginForm()
                msg = 'Token is missing the TOTP secret!'
                return render_template('login.html', form=form, msg=msg)

        except jwt.ExpiredSignatureError:
            form = LoginForm()
            msg = 'Token expired!'
            return render_template('login.html', form=form, msg=msg)
        except jwt.InvalidTokenError:
            form = LoginForm()
            msg = 'Invalid token!'
            return render_template('login.html', form=form, msg=msg)

    return render_template('verify_google_auth.html', form=form, qr_code_url=qr_code_url)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        username = sanitize_input(username)
        email = sanitize_email(email)
        email = is_valid_email(email)
        if email is None:
            msg = 'Please enter a valid email address.'
            return render_template('forgot_password.html', form=form, msg=msg)
        username = encode_input(username)
        email = encode_input(email)
        cursor = mysql.connection.cursor()
        try:
            cursor.execute("SELECT id, phone_number, totp_secret, email, symmetric_key FROM accounts WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                id, phone_number, totp_secret, encrypted_email, symmetric_key = user

                key = symmetric_key
                key = base64.urlsafe_b64decode(key.encode('utf-8'))
                f = Fernet(key)

                # Decrypt the email
                decrypted_email = f.decrypt(encrypted_email.encode()).decode()

                if decrypted_email == email:
                    otp = generate_otp()
                    token = jwt.encode({
                        'id': id,
                        'otp': otp,
                        'username': username,
                        'email': email,
                        'otp_sent_at': datetime.utcnow().isoformat()  # Add timestamp for OTP expiry
                    }, private_key, algorithm='RS256')

                    msg = Message('Password Reset OTP', sender='your_email@example.com', recipients=[decrypted_email])
                    msg.body = f'Your OTP is {otp}'
                    mail.send(msg)

                    resp = make_response(redirect(url_for('verify_reset_otp')))
                    resp.set_cookie('user_data', token, httponly=True, secure=True, max_age=10 * 60)  # 10 minutes
                    return resp
                else:
                    msg = 'Email not found.'
                    return render_template('forgot_password.html', form=form, msg=msg)
            else:
                msg = 'Username not found.'
                return render_template('forgot_password.html', form=form, msg=msg)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            cursor.close()
    return render_template('forgot_password.html', form=form)

@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    form = OTPForm()
    token = request.cookies.get('user_data')
    if not token:
        form = ForgotPasswordForm()
        msg = 'No OTP token found!'
        return render_template('forgot_password.html', form=form, msg=msg)

    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        if form.validate_on_submit():
            otp_from_token = data['otp']
            otp = form.otp.data
            otp = sanitize_otp(otp)
            otp = is_valid_otp(otp)
            if otp is None:
                msg = 'Please enter a valid OTP.'
                return render_template('verify_reset_otp.html', form=form, msg=msg)
            otp = encode_input(otp)

            if otp == otp_from_token:
                resp = make_response(redirect(url_for('reset_password')))
                return resp
            else:
                msg = 'Incorrect OTP'
                return render_template('verify_reset_otp.html', form=form, msg=msg)
        return render_template('verify_reset_otp.html', form=form)
    except jwt.ExpiredSignatureError:
        form = ForgotPasswordForm()
        msg = 'Token expired!'
        return render_template('forgot_password.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = ForgotPasswordForm()
        msg = 'Invalid token!'
        return render_template('forgot_password.html', form=form, msg=msg)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    token = request.cookies.get('user_data')
    if not token:
        form = ForgotPasswordForm()
        msg = 'No OTP token found!'
        return render_template('forgot_password.html', form=form, msg=msg)

    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        if form.validate_on_submit():
            id = data['id']
            password = form.password.data
            username = data['username']
            password = sanitize_password(password)
            password = is_valid_password(password)
            if password is None:
                msg = 'Please enter a valid password.'
                return render_template('reset_password.html', form=form, msg=msg)
            password = encode_input(password)

            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE accounts SET password = %s WHERE username = %s",
            (bcrypt.generate_password_hash(password).decode('utf-8'), username))
            mysql.connection.commit()
            cursor.close()

            password_expiry_days = 90
            password_expiry = datetime.now() + timedelta(days=password_expiry_days)
            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE accounts SET password_expiry = %s WHERE username = %s",
                           (password_expiry, username))
            mysql.connection.commit()
            cursor.close()

            action = f"{username} changed password successfully"
            background_color = "lightgreen"
            log_action1(id, action, background_color)
            resp = make_response(redirect(url_for('login')))
            resp.delete_cookie('user_data')
            return resp

        return render_template('reset_password.html', form=form)
    except jwt.ExpiredSignatureError:
        form = ForgotPasswordForm()
        msg = 'Token expired!'
        return render_template('forgot_password.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = ForgotPasswordForm()
        msg = 'Invalid token!'
        return render_template('forgot_password.html', form=form, msg=msg)




# Set up the URLSafeTimedSerializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Placeholder for Twilio client setup
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


app.config['SERVER_NAME'] = '127.0.0.1:8443'
app.config['APPLICATION_ROOT'] = '/'
app.config['PREFERRED_URL_SCHEME'] = 'https'
# Salt for password reset tokens
app.config['SECURITY_PASSWORD_SALT'] = 'your_random_salt_value'
from datetime import datetime, timedelta


def generate_reset_token(user_id, private_key):
    # Create a payload with a user identifier and expiration time
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }

    # Generate the token using the private key for signing
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token
def send_password_reset_email(user, private_key, expired=False):
    try:
        email = user['email']
        username = user['username']
        symmetric_key = user['symmetric_key']
        user_id = user['id']

        # Decode the symmetric key
        key = base64.urlsafe_b64decode(symmetric_key.encode('utf-8'))

        # Initialize Fernet with the decoded key
        fernet = Fernet(key)

        # Decrypt the email
        decrypted_email = fernet.decrypt(email.encode()).decode()

        # Generate the reset token including the user_id
        token = generate_reset_token(user_id, private_key)

        # Define the local base URL for testing
        local_base_url = 'https://127.0.0.1:8443'
        reset_url = url_for('password_reset_reminder', token=token, _external=False)
        full_reset_url = f"{local_base_url}{reset_url}"

        # Prepare the email message based on the expiration status
        if expired:
            subject = "Account Expired"
            message_body = f"""
            Dear {username},

            Your account has expired. Please click the link below to reset your password and regain access:

            {full_reset_url}

            This link will expire in 1 hour.

            If you did not request this, please ignore this email.

            Best regards,
            Your Company
            """
        else:
            subject = "Password Expiry Reminder"
            message_body = f"""
            Dear {username},

            Your password is about to expire. Please click the link below to reset your password:

            {full_reset_url}

            This link will expire in 1 hour.

            If you did not request this, please ignore this email.

            Best regards,
            Your Company
            """

        # Send the email
        msg = Message(
            subject,
            sender='your_email@example.com',  # Replace with your sender email
            recipients=[decrypted_email]
        )
        msg.body = message_body

        mail.send(msg)

    except Exception as e:
        print(f"An error occurred while sending password reset email: {str(e)}")
def check_password_expiry():
    with app.app_context():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Query to find users whose passwords are either expired or about to expire
        cursor.execute('''
            SELECT id, username, email, symmetric_key, password_expiry
            FROM accounts 
            WHERE password_expiry <= NOW() + INTERVAL 1 DAY
        ''')

        users = cursor.fetchall()
        cursor.close()

        for user in users:
            if user['password_expiry'] <= datetime.now():
                # Account already expired
                send_password_reset_email(user, private_key, expired=True)
            else:
                # Password expiry reminder
                send_password_reset_email(user, private_key, expired=False)

@app.route('/password_reset_reminder/<token>', methods=['GET', 'POST'])
def password_reset_reminder(token):
    form = Password_Reset_Reminder()

    if request.method == 'POST':
        print("Form submission detected.")  # Debug: Confirm form submission

        if form.validate_on_submit():
            print("Form validation passed.")  # Debug: Form passed validation

            try:
                # Debug: Print the token for inspection
                print(f"Received token: {token}")

                # Decode the JWT token
                data = jwt.decode(token, public_key, algorithms=["RS256"])

                # Debug: Check if data and user_id were extracted correctly
                print(f"Decoded token data: {data}")

                user_id = data['user_id']

                # Debug: Check the user_id extracted from the token
                print(f"User ID from token: {user_id}")

                new_password = form.password.data
                new_password = sanitize_password(new_password)

                # Debug: Check the sanitized password
                print(f"Sanitized password: {new_password}")

                if new_password is None:
                    msg = 'Please enter a valid password.'
                    print(msg)
                    return render_template('password_reset_reminder.html', form=form, token=token, msg=msg)

                new_password = encode_input(new_password)

                # Debug: Check the encoded password
                print(f"Encoded password: {new_password}")
                password_expiry_days = 90
                password_expiry = datetime.now() + timedelta(days=password_expiry_days)
                # Update the password in the database
                cursor = mysql.connection.cursor()
                cursor.execute("UPDATE accounts SET password = %s WHERE id = %s",
                               (bcrypt.generate_password_hash(new_password).decode('utf-8'), user_id))
                mysql.connection.commit()
                cursor.execute("UPDATE accounts SET password_expiry = %s WHERE id = %s",
                               (password_expiry, user_id))
                mysql.connection.commit()
                cursor.close()

                resp = make_response(redirect(url_for('login')))
                resp.delete_cookie('user_data')
                return resp

            except jwt.ExpiredSignatureError:
                msg = 'Token expired!'
                print("Token expired.")
                return render_template('login.html', form=LoginForm(), msg=msg)
            except jwt.InvalidTokenError:
                msg = 'Invalid token!'
                print("Invalid token.")
                return render_template('login.html', form=LoginForm(), msg=msg)
            except Exception as e:
                # Log the exception details for debugging
                print(f"An error occurred while resetting the password: {str(e)}")
                msg = 'An error occurred. Please try again.'
                return render_template('password_reset_reminder.html', form=form, token=token, msg=msg)
        else:
            # Debug: If the form validation fails, print the errors
            print("Form validation failed.")
            print(form.errors)

    # Debug: Check if the form was rendered correctly when the method is GET
    print("Rendering password reset form.")
    return render_template('password_reset_reminder.html', form=form, token=token)


@app.route('/MyWebApp/profile', methods=['GET', 'POST'])
@token_required
def profile():
    token = request.cookies.get('jwt')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        encrypted_email = account['email'].encode()
        key = base64.urlsafe_b64decode(account['symmetric_key'].encode('utf-8'))
        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email).decode('utf-8')

        # Initialize the form with the current email notification setting
        form = ProfileForm()

        if request.method == 'POST' and form.validate_on_submit():
            email_notifications = 1 if form.email_notifications.data else 0
            cursor.execute("UPDATE accounts SET email_notifications = %s WHERE username = %s", (email_notifications, username))
            mysql.connection.commit()
            msg1 = 'Profile updated successfully'

            # Refresh the account data to update the form checkbox state
            account['email_notifications'] = email_notifications
            return render_template('profile.html', form=form, account=account, msg1=msg1, decrypted_email=decrypted_email)

        # Set the form checkbox state based on the latest account data
        form.email_notifications.data = bool(account['email_notifications'])

        return render_template('profile.html', form=form, account=account, decrypted_email=decrypted_email)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)
    finally:
        cursor.close()



@app.route('/MyWebApp/profile_admin', methods=['GET', 'POST'])
@token_required
def profile_admin():
    token = request.cookies.get('jwt')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        encrypted_email = account['email'].encode()
        key = base64.urlsafe_b64decode(account['symmetric_key'].encode('utf-8'))
        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email).decode('utf-8')

        # Initialize the form with the current email notification setting
        form = ProfileForm()

        # Set the form checkbox state based on the current account data
        form.email_notifications.data = bool(account['email_notifications'])

        if request.method == 'POST':
            # Capture the checkbox value manually
            email_notifications = 1 if 'email_notifications' in request.form else 0
            print("Form submission email_notifications status:", email_notifications)  # Debug: Check form data

            cursor.execute("UPDATE accounts SET email_notifications = %s WHERE username = %s", (email_notifications, username))
            mysql.connection.commit()

            # Debug: Confirm database update
            cursor.execute('SELECT email_notifications FROM accounts WHERE username = %s', (username,))
            updated_status = cursor.fetchone()['email_notifications']
            print("Updated email_notifications status in DB:", updated_status)

            msg1 = 'Profile updated successfully'

            # Refresh the account data to update the form checkbox state
            account['email_notifications'] = updated_status
            return render_template('profile_admin.html', form=form, account=account, msg1=msg1, decrypted_email=decrypted_email)

        # Debug: Final form checkbox state before rendering
        print("Final form email_notifications state:", form.email_notifications.data)

        return render_template('profile_admin.html', form=form, account=account, decrypted_email=decrypted_email)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)
    finally:
        cursor.close()




@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('home')))
    resp.delete_cookie('jwt')
    return resp

@app.route('/MyWebApp/verf', methods=['GET', 'POST'])
def verf():
    try:
        result = modules.streaming.analysis("static/faces", enable_face_analysis=False, anti_spoofing=True)
        if result["status"] == "success" and result["verified"] == True:
            target_img = result["target_label"]
        elif result["status"] == "spoofed":
            target_img = result["target_label"]
            target_img = os.path.normpath(target_img).replace("\\", "/")
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE image_pathLocation = %s', (target_img,))
            account = cursor.fetchone()
            if account:
                id = account['id']
                username = account['username']
                action = f"{username} failed to login through face recognition using image"
                background_color = "crimson"
                log_action1(id, action, background_color)
                return redirect(url_for("login"))
        elif result["status"] == "success" and result["verified"] == False:
            target_img = result["target_label"]
            target_img = os.path.normpath(target_img).replace("\\", "/")
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE image_pathLocation = %s', (target_img,))
            account = cursor.fetchone()
            if account:
                id = account['id']
                username = account['username']
                action = f"{username} failed to login through face recognition using image"
                background_color = "crimson"
                log_action1(id, action, background_color)
                return redirect(url_for("login"))
        else:
            return redirect(url_for("login"))

        target_img = os.path.normpath(target_img).replace("\\", "/")
        if request.method == 'POST':
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE image_pathLocation = %s', (target_img,))
            account = cursor.fetchone()
            if account:
                id = account['id']
                username = account['username']
                action = f"{username} login through face recognition"
                background_color = "lightgreen"
                log_action1(id, action, background_color)
                if result["status"] == "no_face":
                    msg = 'Please face the camera and try again.'
                    return render_template('login.html', msg=msg, form=LoginForm())
                if account['email_notifications'] == 1:
                    encrypted_email = account['email'].encode()
                    key = base64.urlsafe_b64decode(account['symmetric_key'].encode('utf-8'))
                    f = Fernet(key)
                    decrypted_email = f.decrypt(encrypted_email).decode('utf-8')
                    # Create the email subject and body
                    subject = 'Important: Login Notification'
                    body = (f"Dear {username},\n\n"
                            f"We wanted to let you know that your account was accessed on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}.\n\n"
                            f"If you did not initiate this login, please take the following actions immediately:\n"
                            f"- Change your password.\n"
                            f"- Review your recent account activity.\n"
                            f"- Contact our support team if you have any concerns.\n\n"
                            f"If this was you, there's no need to take further action.\n\n"
                            f"Thank you for your attention to this matter.\n\n"
                            f"Best regards,\n"
                            f"The [Laundromat] Team\n\n"
                            f"Contact Us:\n"
                            f"Email: support@example.com\n"
                            f"Phone: +123-456-7890\n"
                            f"Website: www.example.com\n\n"
                            f"---\n"
                            f"This is an automated notification. Please do not reply to this email.")

                    # Create and send the email
                    msg = Message(subject, sender='noreply@example.com', recipients=[decrypted_email])
                    msg.body = body
                    mail.send(msg)
                user_data = jwt.encode({
                    'id': account['id'],
                    'role': account['is_admin'],
                    'username': account['username'],
                    'totp_secret': account['totp_secret'],
                    'otp_sent_at': datetime.utcnow().isoformat()},
                    private_key, algorithm='RS256')
                response = make_response(redirect(url_for('choice')))
                response.set_cookie('user_data', user_data, httponly=True, secure=True, max_age=10*60)
                return response
            else:
                msg = "Please register an account first!"
                return render_template('login.html', msg=msg, form=LoginForm())
    except:
        msg = "Please face the camera!"
        return render_template('login.html', msg=msg, form=LoginForm())

@app.route('/MyWebApp/add_face', methods=['POST'])
@token_required
def add_face():
    token = request.cookies.get('jwt')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        create_face_form = CreateFaceForm()
        encrypted_email = account['email'].encode()
        key = account['symmetric_key']
        key = base64.urlsafe_b64decode(key.encode('utf-8'))
        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email)
        if request.method == 'POST' and create_face_form.validate():
            face = request.files['face']

            if face.filename == '':
                return redirect(url_for('profile'))

            if allowed_file(face.filename):
                filename = f"{account['id']}.jpg"
                filename = secure_filename(filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file_path = file_path.replace("\\", "/")
                face.save(file_path)

                if validate_file_type(file_path):
                    image_path = file_path
                    analysis = modules.demography.analyze(img_path=image_path, actions=['emotion'],
                                                          enforce_detection=False)
                    for item in analysis:
                        if isinstance(item, dict) and 'face_confidence' in item:
                            if float(item['face_confidence']) >= 0.70:
                                cursor.execute('UPDATE accounts SET image_pathLocation = %s WHERE username = %s;',
                                               (image_path, username,))
                                mysql.connection.commit()
                                msg = "Successfully added your face for facial recognition login"
                                action = f"{username} successfully added a face for facial recognition login"
                                background_color = "lightgreen"
                                log_action(action, background_color)
                                form = ProfileForm()
                                return render_template('profile.html', account=account,
                                                       decrypted_email=decrypted_email.decode('utf-8'), msg=msg, form=form)
                            else:
                                os.remove(file_path)
                                cursor.execute('UPDATE accounts SET image_pathLocation = NULL WHERE username = %s;',
                                               (username,))
                                mysql.connection.commit()
                                action = f"{username} failed to add a face for facial recognition login"
                                background_color = "crimson"
                                log_action(action, background_color)
                                form = ProfileForm()
                                msg = "Please upload an image with a face in it"
                                return render_template('profile.html', account=account,
                                                       decrypted_email=decrypted_email.decode('utf-8'), msg=msg, form=form)
                else:
                    os.remove(file_path)
                    form = ProfileForm()
                    msg = "Invalid file type"
                    return render_template('profile.html', account=account,
                                           decrypted_email=decrypted_email.decode('utf-8'), msg=msg, form=form)
            else:
                msg = "File type not allowed"
                form = ProfileForm()
                return render_template('profile.html', account=account, decrypted_email=decrypted_email.decode('utf-8'),
                                       msg=msg, form=form)

    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)


@app.route('/MyWebApp/add_face_admin', methods=['POST'])
@token_required
def add_face_admin():
    token = request.cookies.get('jwt')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        create_face_form = CreateFaceForm()
        encrypted_email = account['email'].encode()
        key = account['symmetric_key']
        key = base64.urlsafe_b64decode(key.encode('utf-8'))
        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email)
        if request.method == 'POST' and create_face_form.validate():
            face = request.files['face']

            if face.filename == '':
                return redirect(url_for('profile'))
            if allowed_file(face.filename):
                face.filename = os.path.normpath(face.filename).replace(f"{face.filename}", f"{account['id']}.jpg")
                filename = secure_filename(face.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file_path = file_path.replace("\\", "/")
                face.save(file_path)
                if validate_file_type(file_path):
                    image_path = file_path
                    image_path = f"static/faces/{face.filename}"
                    analysis = modules.demography.analyze(img_path=image_path, actions=['emotion'], enforce_detection=False)
                    for item in analysis:
                        if isinstance(item, dict) and 'face_confidence' in item:
                                if float(item['face_confidence']) >= 0.70:
                                    pass
                                else:
                                    os.remove(image_path)
                                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                                    cursor.execute('UPDATE accounts SET image_pathLocation = NULL WHERE username = %s;', (username,))
                                    mysql.connection.commit()
                                    action = f"{username} failed to add a face for facial recognition login"
                                    background_color = "crimson"
                                    log_action(action, background_color)
                                    form = ProfileForm()
                                    msg = "Please upload an image with a face in it"
                                    return render_template('profile_admin.html', account=account, decrypted_email=decrypted_email.decode('utf-8'), msg=msg, form=form)
                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    cursor.execute('UPDATE accounts SET image_pathLocation = %s WHERE username = %s;', (image_path, username,))
                    mysql.connection.commit()
                    msg = "Successfully added your face for facial recognition login"
                    action = f"{username} successfully added a face for facial recognition login"
                    background_color = "lightgreen"
                    log_action(action, background_color)
                    form = ProfileForm()
                    return render_template('profile_admin.html', account=account, form=form, decrypted_email=decrypted_email.decode('utf-8'), msg=msg)
                else:
                    os.remove(filename)
                    msg = "Invalid file type"
                    form = ProfileForm()
                    return render_template('profile_admin.html', account=account,
                                       decrypted_email=decrypted_email.decode('utf-8'), msg=msg, form=form)
            else:
                msg = "File type not allowed"
                form = ProfileForm()
                return render_template('profile_admin.html', account=account,
                                       decrypted_email=decrypted_email.decode('utf-8'), msg=msg, form=form)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

def log_action(action, background_color):
    token = request.cookies.get('jwt')
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        id = data['id']
        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO logging (user_id, action, background_color) VALUES (%s, %s, %s)',
                       (id, action, background_color))
        mysql.connection.commit()
        cursor.close()
        return
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

def log_action1(id, action, background_color):
    cursor = mysql.connection.cursor()
    cursor.execute('INSERT INTO logging (user_id, action, background_color) VALUES (%s, %s, %s)',
    (id, action,background_color))
    mysql.connection.commit()
    cursor.close()
    return

@app.route('/logs')
def display_logs():
    token = request.cookies.get('jwt')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        id = data['id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT action, timestamp, background_color FROM logging WHERE user_id = %s", (id,))
        logs = cursor.fetchall()
        cursor.close()
        return render_template('logs.html', logs=logs)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

@app.route('/logs_admin')
def display_logs_admin():
    token = request.cookies.get('jwt')
    if not token:
        form = LoginForm()
        msg = 'Token is missing!'
        return render_template('login.html', form=form, msg=msg)
    try:
        data = jwt.decode(token, public_key, algorithms=["RS256"])
        username = data['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch the logged-in user's account details
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        # Fetch all user accounts for the admin view, excluding the root account
        cursor.execute('SELECT id, username, email, is_admin, symmetric_key FROM accounts WHERE username != %s',
                       ('root',))
        accounts = cursor.fetchall()

        # Decrypt emails for each account
        for acc in accounts:
            encrypted_email = acc['email'].encode()
            if 'symmetric_key' in acc:
                key = acc['symmetric_key']
                key = base64.urlsafe_b64decode(key.encode('utf-8'))
                f = Fernet(key)
                acc['decrypted_email'] = f.decrypt(encrypted_email).decode('utf-8')
            else:
                acc['decrypted_email'] = "Key not available"
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT action, timestamp, background_color FROM logging")
        logs = cursor.fetchall()
        cursor.close()
        return render_template('logs_admin.html', logs=logs, account=account, accounts=accounts)
    except jwt.ExpiredSignatureError:
        form = LoginForm()
        msg = 'Token expired!'
        return render_template('login.html', form=form, msg=msg)
    except jwt.InvalidTokenError:
        form = LoginForm()
        msg = 'Invalid token!'
        return render_template('login.html', form=form, msg=msg)

@app.route("/privacy")
def privacy_policy():
    return render_template("privacy.html")

@app.route("/terms")
def terms_of_service():
    return render_template("terms.html")

if __name__== '__main__' :
    check_password_expiry()
    app.run( port=8443, ssl_context=(r'C:\key\sherman.infinityfreeapp.com.crt',r'C:\key\sherman.infinityfreeapp.com.key'))