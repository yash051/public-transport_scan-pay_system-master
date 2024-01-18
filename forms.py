from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    # user_rfid = StringField("User RFID", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class GetUserForm(FlaskForm):
    user_email = EmailField("Email", validators=[DataRequired()])
    submit = SubmitField("Get user")


class AddRfid(FlaskForm):
    user_rfid = StringField("Name", validators=[DataRequired()])
    confirm_email = EmailField("User Email", validators=[DataRequired()])
    submit = SubmitField("Add RFID")