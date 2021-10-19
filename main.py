from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LogInForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='identicon', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "Users.id" the users refers to the table_name of User.
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    # Create reference to the Users object, the "posts" refers to the posts property in the Users class.
    author = relationship("Users", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Create one blog post to many comments relationship
    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")

# db.create_all()

class Users(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000), nullable=False)

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")

    # *******Add parent relationship*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # *******Add child relationship*******#
    # "Users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the Users class.
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    comment_author = relationship("Users", back_populates="comments")
    # Create one blog post to many comments relationship
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # ***************Child Relationship*************#
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)

db.create_all()

# Create a function that just allows admin to edit/create/delete posts.
def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
        # If id is not 1 then return abort with 403 error
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return wrapper

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if Users.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
        else:
            new_user = Users(
                email=form.email.data,
                password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8),
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            login_user(new_user)

            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)

# Create a user_loader function
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LogInForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user = Users.query.filter_by(email=user_email).first()
        if user == None:
            flash("The email address does not exist. Please try again!")
        elif not check_password_hash(pwhash=user.password, password=form.password.data):
            flash("Password incorrect. Please try again!")
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment!")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete-comment/<int:comment_id>")
def delete_comment(comment_id):
    comment_to_delete = Comment.query.filter_by(id=comment_id).first()
    post_to_return = BlogPost.query.filter_by(id=comment_to_delete.post_id).first()
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_to_return.id))

if __name__ == "__main__":
    app.run(debug=True)
