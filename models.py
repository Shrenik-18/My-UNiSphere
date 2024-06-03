import datetime
from flask_bcrypt import generate_password_hash
from flask_login import UserMixin
from peewee import *

DATABASE = SqliteDatabase('social.db')

class BaseModel(Model):
    class Meta:
        database = DATABASE

class User(UserMixin, BaseModel):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=100)
    joined_at = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)
    
    class Meta:
        order_by = ('-joined_at',)
        
    def get_posts(self):
        return Post.select().where(Post.user == self)
    
    def get_stream(self):
        return Post.select().where(
            (Post.user << self.following()) |
            (Post.user == self)
        )
    
    def following(self):
        return (
            User.select().join(
                Relationship, on=Relationship.to_user
            ).where(
                Relationship.from_user == self
            )
        )
    
    def followers(self):
        return (
            User.select().join(
                Relationship, on=Relationship.from_user
            ).where(
                Relationship.to_user == self
            )
        )
    
    @classmethod
    def create_user(cls, username, email, password, admin=False):
        try:
            with DATABASE.transaction():
                cls.create(
                    username=username,
                    email=email,
                    password=generate_password_hash(password).decode('utf-8'),
                    is_admin=admin
                )
        except IntegrityError:
            raise ValueError("User already exists")

class Post(BaseModel):
    timestamp = DateTimeField(default=datetime.datetime.now)
    user = ForeignKeyField(User, backref='posts')
    content = TextField()
    
    class Meta:
        order_by = ('-timestamp',)
            
class Relationship(BaseModel):
    from_user = ForeignKeyField(User, backref='relationships')
    to_user = ForeignKeyField(User, backref='related_to')
    
    class Meta:
        indexes = (
            (('from_user', 'to_user'), True),
        )

def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User, Post, Relationship], safe=True)
    DATABASE.close()
