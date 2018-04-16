from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
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

db = SqliteDatabase('app.db')

login = LoginManager(app)
login.login_view = 'login'

class LoginForm(FlaskForm):
    email = StringField('Caltech email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log in')

class RegistrationForm(FlaskForm):
    email = StringField('Caltech email', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.get(User.email == email.data)
        if user is None:
            raise ValidationError('Caltech email address not found')

'''like = db.Table('likes',
        db.Column('liker_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
        db.Column('liked_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
)'''


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

def make_password(length, alphabet):
    #return ''.join(random.choice(alphabet) for _ in range(length))
    return 'p'

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
        #try:
        with db:
            user = User.get(User.email == form.email.data)
        #except
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
    success = False
    form = RegistrationForm()
    if form.validate_on_submit():
        #try:
        with db:
            user = User.get(User.email == form.email.data)
            #if(user.registered == 0):
            if(True):
                user.registered = 1
                user.subscribed = 1
                password = make_password(8, string.ascii_letters)
                user.set_password(password)
                user.save()
                flash('Password: ' + password)
        flash('Check your email. If you are not already registered, you will have received an email with a temp password.')
        success = True
        #except User.DoesNotExist:
            #flash('This user does not exist')

    if success:
        return redirect(url_for('login'))
    else:
        return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    users = User.select()
    if request.method == 'POST':
        result = request.form
        new_likes = []
        for key, _ in result.items():
            try:
                liked_user = User.get(User.id == int(key))
                if liked_user is not None:
                    new_likes.append((current_user, liked_user))
            except ValueError:
                pass

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
                        if current_user.subscribed:
                            flash('New match with {}!'.format(their_user.name))
                        if their_user.subscribed:
                            flash('They have been notified!')
                        their_like.notified = 1
                        their_like.save()
                        my_like.notified = 1
                        my_like.save()

    return render_template('index.html', current_user=current_user, users=users, likes=liked_users, matches=matched_users)
