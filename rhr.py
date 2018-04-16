from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from peewee import *
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import string
import csv
import random
import datetime

app = Flask(__name__)
app.config.from_object('config.Config')
app.config.from_object('instance.config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login = LoginManager(app)
login.login_view = 'login'

class LoginForm(FlaskForm):
    email = StringField('Caltech email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log in')

class RegistrationForm(FlaskForm):
    email = StringField('Caltech email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Caltech email address not found')
        if user.registered:
            raise ValidationError('Email address already registered')

'''like = db.Table('likes',
        db.Column('liker_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
        db.Column('liked_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
)'''



class Like(db.Model):
    liker_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    liked_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, unique=True)
    name = db.Column(db.String(120), index=True)
    password_hash = db.Column(db.String(128))
    registered = db.Column(db.Boolean)
    subscribed = db.Column(db.Boolean)
    liked = db.relationship("Like", backref="liked", primaryjoin=id==Like.liked_id)
    liker = db.relationship("Like", backref="liker", primaryjoin=id==Like.liker_id)

    def __repr__(self):
        return '<User {}>'.format(self.email)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def make_password(length, alphabet):
    return ''.join(random.choice(alphabet) for _ in range(length))

@login.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

@app.route('/login', methods=['GET', 'POST'])
def login():
    users = User.query.all()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password')
            return redirect(url_for('login'))
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
        user = User.query.filter_by(email=form.email.data).first()
        password = make_password(8, string.ascii_letters)
        user.set_password(password)
        db.session.commit()
        flash('Password: ' + password)
        flash('You are now a registered user')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    users = User.query.all()
    current_likes = Like.query.filter_by(liker_id=current_user.id)
    if request.method == 'POST':
        result = request.form
        new_likes = []
        for key, _ in result.items():
            liked_user = User.query.get(key)
            if liked_user is not None:
                new_likes.append(Like(liker=current_user, liked=liked_user))

        if(len(new_likes) > app.config['MAX_CHECKS']):
            flash('Error: you can\'t check more than {} people.'.format(app.config['MAX_CHECKS']))
        else:
            for like in current_likes:
                if like not in new_likes:
                    db.session.delete(like)
                    db.session.commit()
            for like in new_likes:
                if like not in current_likes:
                    db.session.add(like)
                    db.session.commit()

    liked_users = [like.liked for like in current_user.liker]
    matches = [like.liker for like in current_user.liked if like.liker in liked_users]
    return render_template('index.html', users=users, likes=liked_users, matches=matches)
