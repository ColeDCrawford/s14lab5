from dotenv import load_dotenv
from flask import Flask, flash, render_template, request, url_for, redirect, jsonify, session
from models.models import Db, User, Post
from forms.forms import SignupForm, LoginForm, NewpostForm
from os import environ
from passlib.hash import sha256_crypt
from datetime import datetime

load_dotenv('.flaskenv')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = environ.get('SECRET_KEY')
Db.init_app(app)

# GET /
@app.route('/')
@app.route('/index')
def index():
    # Control by login status
    if 'username' in session:
        session_user = User.query.filter_by(username=session['username']).first()
        user_posts = Post.query.filter_by(author=session_user.uid).order_by(Post.pid.desc()).all()
        other_posts = Post.query.filter(Post.author!=session_user.uid).order_by(Post.pid.desc()).all()
        print(other_posts)
        return render_template('index.html.j2', title='Home', user_posts=user_posts, other_posts=other_posts, session_username=session_user.username)
    else:
        all_posts = Post.query.order_by(Post.pid.desc()).all()
        return render_template('index.html.j2', title='Home', other_posts=all_posts)


#GET & POST /login
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Init form
    form = LoginForm()

    # If post
    if request.method == 'POST':

        # Init credentials from form request
        username = request.form['username']
        password = request.form['password']

        # Init user by Db query
        user = User.query.filter_by(username=username).first()

        # Control login validity
        if user is None or not sha256_crypt.verify(password, user.password):
            flash('Invalid username or password', 'alert-danger')
            return redirect(url_for('login'))
        else:
            session['username'] = username
            flash('Logged in successfully', 'alert-success')
            return redirect(url_for('index'))

    # If GET
    else:
        return render_template('login.html.j2', title='Login', form=form)


#POST /logout
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    # Logout
    session.clear()
    return redirect(url_for('index'))


#GET & POST /newpost
@app.route('/newpost', methods=['GET', 'POST'])
def newpost():
    # Init form
    form = NewpostForm()

    # If POST
    if request.method == 'POST':

        # Init user from poster
        session_user = User.query.filter_by(username=session['username']).first()

        # Init content from form request
        content = request.form['content']
        title = request.form['title']

        # Create in DB
        now = datetime.now()
        new_post = Post(author=session_user.uid, content=content, created_date=now, title=title)
        Db.session.add(new_post)
        Db.session.commit()

        flash('Post created', 'alert-success')
        return redirect(url_for('index'))

    # If GET
    else:
        return render_template('newpost.html.j2', title='Newpost', form=form)


#GET & POST /signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Init form
    form = SignupForm()

    # IF POST
    if request.method == 'POST':

        # Init credentials from form request
        username = request.form['username']
        password = request.form['password']

        # Init user from Db query
        existing_user = User.query.filter_by(username=username).first()

        # Control new credentials
        if existing_user:
            flash('The username already exists. Please pick another one.', 'alert-warning')
            return redirect(url_for('signup'))
        else:
            user = User(username=username, password=sha256_crypt.hash(password))
            Db.session.add(user)
            Db.session.commit()
            flash('Congratulations, you are now a registered user!', 'alert-success')
            return redirect(url_for('login'))

    # IF GET
    else:
        return render_template('signup.html.j2', title='Signup', form=form)
