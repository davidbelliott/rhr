from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from peewee import *
import wtforms
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import string
import csv
import random
import datetime
import os
import smtplib  
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Email sender address
SENDER = 'noreply@rhr.fun'  
SENDERNAME = 'RHR'
# Amazon SES SMTP user name.
USERNAME_SMTP = "AKIAIEDODYRTIGBHLAQQ"

# Amazon SES SMTP password.
PASSWORD_SMTP = "AmkkRNWkVU+JrHBoEmrhBj9Uks/LS9NaD7HhFTR7J0B/"

# If you're using Amazon SES in an AWS Region other than US West (Oregon), 
# replace email-smtp.us-west-2.amazonaws.com with the Amazon SES SMTP  
# endpoint in the appropriate region.
HOST = "email-smtp.us-west-2.amazonaws.com"
PORT = 587

def send_msg(subject, recipient, text):
    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = email.utils.formataddr((SENDERNAME, SENDER))
    msg['To'] = recipient

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(text, 'plain')
    #part2 = MIMEText(html, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    #msg.attach(part2)

    # Try to send the message.
    try:  
        server = smtplib.SMTP(HOST, PORT)
        server.ehlo()
        server.starttls()
        #stmplib docs recommend calling ehlo() before & after starttls()
        server.ehlo()
        server.login(USERNAME_SMTP, PASSWORD_SMTP)
        server.sendmail(SENDER, RECIPIENT, msg.as_string())
        server.close()
    # Display an error message if something goes wrong.
    except Exception as e:
        print ("Error: ", e)
    else:
        print ("Email sent!")


app = Flask(__name__)
app.config.from_object('config.Config')
app.config.from_object('instance.config')

db = SqliteDatabase('app.db')

login = LoginManager(app)
login.login_view = 'login'

class LoginForm(FlaskForm):
    email = wtforms.StringField('Caltech email', validators=[DataRequired(), Email()])
    password = wtforms.PasswordField('Password', validators=[DataRequired()])
    submit = wtforms.SubmitField('Log in')

class RegistrationForm(FlaskForm):
    email = wtforms.StringField('Caltech email', validators=[DataRequired(), Email()])
    eighteen = wtforms.BooleanField('18 or over?', validators=[DataRequired(message='You must certify you are 18 or over to proceed.')])
    submit = wtforms.SubmitField('Register')

    def validate_email(self, email):
        user = User.get(User.email == email.data)
        if user is None:
            raise ValidationError('Caltech email address not found')

class ChangePasswordForm(FlaskForm):
    password = wtforms.PasswordField('Current password', validators=[DataRequired()])
    new_password = wtforms.PasswordField('New password', validators=[DataRequired(), EqualTo('new_password_2', message='Passwords must match')])
    new_password_2 = wtforms.PasswordField('Confirm new password', validators=[DataRequired()])
    submit = wtforms.SubmitField('Change password')

class User(UserMixin, Model):
    email = CharField(unique=True)
    name = CharField()
    password_hash = CharField()
    registered = IntegerField()
    subscribed = IntegerField()

    class Meta:
        database = db

    def __repr__(self):
        return '<User {}>'.format(self.email)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def likes(self):
        return (User
            .select()
            .join(Like, on=Like.to_user)
            .where(Like.liker == self))

    def liked_by(self):
        return (User
            .select()
            .join(Like, on=Like.from_user)
            .where(Like.liked == self))

class Like(Model):
    liker = ForeignKeyField(User, backref='likes')
    liked = ForeignKeyField(User, backref='liked_by')
    datetime = DateTimeField()
    notified = IntegerField()

    class Meta:
        database = db
        indexes = (
                (('liker', 'liked'), True),
        )

def create_tables():
    with db:
        db.create_tables([User, Like])

def load_users(filename):
        with open(filename) as tsv:
            with db:
                for line in csv.reader(tsv, dialect="excel-tab"):
                    try:
                        user = User.create(name=line[0], email=line[1], registered=0, subscribed=0, password_hash='')
                    except Exception as e:
                        print("Exception: {}".format(str(e)))
                    print(user)

def make_password(length, alphabet):
    return ''.join(random.choice(alphabet) for _ in range(length))

@login.user_loader
def load_user(user_id):
    return User.get(User.id == user_id)

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    users = User.select()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
	# try to get the user
        found_user = False
        try:
            with db:
                user = User.get(User.email == form.email.data)
            found_user = True
        except User.DoesNotExist:
            user = None
            pass

        if not found_user or not user.check_password(form.password.data): # unsuccessful login
            flash('Invalid email or password')
            return redirect(url_for('login'))
        else: # successful login
            if user.registered == 0: # first login
                user.registered = 1
                user.subscribed = 1
                user.save()
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form=form, users=users)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            with db:
                user = User.get(User.email == form.email.data)
                if(user.registered == 0):
                    password = make_password(8, string.ascii_letters)
                    user.set_password(password)
                    user.save()
                    
                    # Send email with temp password
                    subject = "RHR registration successful"
                    msg = "Your temp password is {}\nIf you did not register, please ignore this email.".format(password)
                    send_msg(subject, user.email, msg)
        except User.DoesNotExist:
            pass
        flash('Check your email. If you are not already registered, you will have received an email with a temp password.')
            
        return redirect(url_for('login'))
    else:
        return render_template('register.html', form=form)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    success = False
    form = ChangePasswordForm()
    if form.validate_on_submit():
        with db:
            if(current_user.check_password(form.password.data)):
                current_user.set_password(form.new_password.data)
                current_user.save()
                flash('Password change success!')
                success = True
            else:
                flash('Incorrect current password')

    if success:
        return redirect(url_for('login'))
    else:
        return render_template('change-password.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    users = User.select()
    if request.method == 'POST':
        result = request.form
        new_likes = []
        subscribed = False
        for key, _ in result.items():
            try:
                liked_user = User.get(User.id == int(key))
                if liked_user is not None:
                    new_likes.append((current_user, liked_user))
            except ValueError: # this is not a user key
                print(key)
                if key == 'emails':
                    subscribed = True
        # Update email preferences
        if subscribed != current_user.subscribed:
            with db:
                current_user.subscribed = subscribed
                current_user.save()

        if(len(new_likes) > app.config['MAX_CHECKS']):
            flash('Error: you can\'t check more than {} people.'.format(app.config['MAX_CHECKS']))
        else:
            with db:
                old_likes = [(like.liker, like.liked) for like in (Like.select().where(Like.liker == current_user.id))]
                for like in new_likes:
                    if not like in old_likes:
                        print(old_likes)
                        print("NEW LIKE!")
                        Like.create(liker=like[0].id, liked=like[1].id, datetime=datetime.datetime.now(), notified=0)
                for like in old_likes:
                    if like not in new_likes:
                        print("DELETE LIKE!")
                        del_like = Like.select().where(Like.liker == like[0], Like.liked == like[1]).get()
                        del_like.delete_instance()

    current_likes = (Like.select().where(Like.liker == current_user.id))
    liked_users = [like.liked for like in current_likes]
    matched_users = []
    with db:
        for my_like in current_likes:
            their_likes = (Like.select().where(Like.liker == my_like.liked))
            their_user = my_like.liked
            for their_like in their_likes:
                if current_user == their_like.liked:
                    matched_users.append(their_like.liker)

                    # Notify of match
                    if my_like.notified == 0 and their_like.notified == 0:
                        flash('New match with {}!'.format(their_user.name))
                        if their_user.subscribed:
                            # send notification email
                            subject = '{} would like to connect with you on RHR'.format(current_user.name)
                            msg = 'Contact them at {}'.format(current_user.email)
                            send_msg(subject, their_user.email, msg)
                            flash('They have been notified.')
                        their_like.notified = 1
                        their_like.save()
                        my_like.notified = 1
                        my_like.save()

    return render_template('index.html', current_user=current_user, users=users, likes=liked_users, matches=matched_users, max_checks=app.config['MAX_CHECKS'])
