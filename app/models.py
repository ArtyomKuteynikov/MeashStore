# models.py

from flask_login import UserMixin
from . import db
from itsdangerous import URLSafeTimedSerializer as Serializer
from . import config


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    token = db.Column(db.String(256))
    status = db.Column(db.String(10), default='active')
    role = db.Column(db.Integer)
    registered = db.Column(db.Integer)
    group = db.Column(db.Integer)
    confirmed = db.Column(db.Integer, default=0)
    tag = db.Column(db.String(256))

    def generate_auth_token(self, expiration=600):
        s = Serializer(config.SECRET_KEY)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(config.SECRET_KEY)
        try:
            data = s.loads(token)
        except:
            return None
        user = User.query.get(data['id'])
        return user


class Codes(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    phone = db.Column(db.String(100))
    code = db.Column(db.String(10))


class ResPass(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    phone = db.Column(db.String(100))
    code = db.Column(db.String(10))


class Groups(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    name = db.Column(db.String(100))


class Beacons(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    uuid = db.Column(db.String(256))
    name = db.Column(db.String(100))
    group = db.Column(db.Integer)


class UserGroups(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    name = db.Column(db.String(100))
    group = db.Column(db.Integer)


class GroupsMapping(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    user_group = db.Column(db.Integer)
    user = db.Column(db.Integer)


class Notifications(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    group = db.Column(db.Integer)
    user_group = db.Column(db.Integer)
    beacon = db.Column(db.Integer)
    time_start = db.Column(db.DateTime)
    time_finish = db.Column(db.DateTime)
    title = db.Column(db.String(100))
    text = db.Column(db.String(10000))
    attachment = db.Column(db.String(100))


class SentNotifications(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    notification = db.Column(db.Integer)
    user = db.Column(db.Integer)
    time = db.Column(db.Integer)


class Backgrounds(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    network = db.Column(db.Integer)
    name = db.Column(db.String(100))
    file = db.Column(db.String(1000))


class Texts(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    network = db.Column(db.Integer)
    name = db.Column(db.String(100))
    title = db.Column(db.String(1000))
    text = db.Column(db.String(10000))
