from flask import Flask, g, render_template, flash, redirect, url_for, abort
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import forms
import models
import logging

DEBUG = True
PORT = 8000
HOST = '0.0.0.0'

app = Flask(__name__)
app.secret_key = 'auoeshbouoastuh43uoausoehuosth3ououeaauoub'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(userid):
    return models.User.get_or_none(models.User.id == userid)

@app.before_request
def before_request():
    g.db = models.DATABASE
    if not g.db.is_closed():
        g.db.close()
    g.db.connect()
    g.user = current_user

@app.after_request
def after_request(response):
    g.db.close()
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data).decode('utf-8')
        try:
            models.User.create(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password
            )
            flash("Yay, you registered!", "success")
            return redirect(url_for('index'))
        except models.IntegrityError:
            flash("User with that email or username already exists.", "error")
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = models.User.get_or_none(models.User.email == form.email.data)
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("You've been logged in!", "success")
            return redirect(url_for('index'))
        flash("Your email or password doesn't match!", "error")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out! Come back soon!", "success")
    return redirect(url_for('index'))

@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def post():
    form = forms.PostForm()
    if form.validate_on_submit():
        models.Post.create(user=g.user.id, content=form.content.data.strip())
        flash('Your Message has been posted!', 'success')
        return redirect(url_for('index'))
    return render_template('post.html', form=form)

@app.route('/')
def index():
    stream = models.Post.select().limit(100)
    return render_template('stream.html', stream=stream)

@app.route('/stream', defaults={'username': None})
@app.route('/stream/<username>')
def user_stream(username):
    template = 'stream.html'
    if username and username != current_user.username:
        user = models.User.get_or_none(models.User.username == username)
        if user:
            stream = user.posts.limit(100)
        else:
            abort(404)
    else:
        stream = current_user.posts.limit(100)
        user = current_user
    if username:
        template = 'user_stream.html'
    return render_template(template, stream=stream, user=user)

@app.route('/follow/<username>')
@login_required
def follow(username):
    to_user = models.User.get_or_none(models.User.username == username)
    if to_user is not None:
        try:
            models.Relationship.create(
                from_user=g.user.id,
                to_user=to_user.id
            )
            flash(f"You are now following {to_user.username}!", 'success')
        except models.IntegrityError:
            flash(f"You are already following {to_user.username}.", 'info')
    else:
        abort(404)
    return redirect(url_for('user_stream', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    to_user = models.User.get_or_none(models.User.username == username)
    if to_user is not None:
        query = models.Relationship.delete().where(
            (models.Relationship.from_user == g.user.id) &
            (models.Relationship.to_user == to_user.id)
        )
        query.execute()
        flash(f"You have unfollowed {to_user.username}.", 'success')
    else:
        abort(404)
    return redirect(url_for('user_stream', username=username))

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    post = models.Post.get_or_none(models.Post.id == post_id)
    if not post:
        abort(404)
    return render_template('view_post.html', post=post)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    models.initialize()
    app.run(debug=DEBUG, host=HOST, port=PORT)
