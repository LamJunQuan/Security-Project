from wtforms import Form, StringField, RadioField, SelectField, SelectMultipleField, validators, PasswordField, IntegerField, TextAreaField, ValidationError, FloatField, TimeField, SubmitField, DecimalField, widgets, BooleanField, PasswordField, HiddenField
from wtforms.fields import EmailField, DateField
from wtforms import widgets, BooleanField
import re
from wtforms.validators import DataRequired, Length, InputRequired, Length, NumberRange, ValidationError, Email
from flask_wtf.file import FileField
from flask_wtf import FlaskForm,RecaptchaField
import datetime
from datetime import date, timedelta, datetime, time
import string
from wtforms.validators import DataRequired, Email, EqualTo
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password1 = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])  # Assuming phone_number is a string field
    submit = SubmitField('Register')

class ForgotPasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')


class Password_Reset_Reminder(FlaskForm):
    password = PasswordField('New Password',
                             validators=[DataRequired(), EqualTo('confirm_password', message='Password must match')])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')


class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired()])
    submit = SubmitField('Verify OTP')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), EqualTo('confirm_password', message='Password must match')])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha=RecaptchaField()
    submit = SubmitField('Login')

class VerificationForm(FlaskForm):
    verification_code = StringField('Verification Code', validators=[DataRequired()])
    submit = SubmitField('Verify')

class CreateFaceForm(Form):
    Face = FileField('Face', [validators.Length(max=50)])

class ChoiceForm(FlaskForm):
    medium = RadioField('Choose your OTP medium', choices=[('phone', 'Phone'), ('email', 'Email'), ('google_auth', 'Google Authenticator')], default='phone')
    submit = SubmitField('Submit')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Update')

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message='Password must match')])
    submit = SubmitField('Change Password')

class ProfileForm(FlaskForm):
    email_notifications = BooleanField('Enable Email Notifications')
    submit = SubmitField('Save Changes')

