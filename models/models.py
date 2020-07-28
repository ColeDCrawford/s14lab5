from flask_sqlalchemy import SQLAlchemy

Db = SQLAlchemy()


class User(Db.Model):
    __tablename__ = 'users'
    uid = Db.Column(Db.Integer, primary_key=True, autoincrement=True)
    username = Db.Column(Db.String(64), unique=True, nullable=False)
    password = Db.Column(Db.String(128), nullable=False)
    posts = Db.relationship('Post', backref='user')


class Post(Db.Model):
    __tablename__ = 'posts'
    pid = Db.Column(Db.Integer, primary_key=True, autoincrement=True)
    author = Db.Column(Db.Integer, Db.ForeignKey('users.uid'), nullable=False)
    title = Db.Column(Db.String(200))
    content = Db.Column(Db.String(1024), nullable=False)
    created_date = Db.Column(Db.Date)
