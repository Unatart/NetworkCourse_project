from flask import render_template, redirect, url_for, request, session, send_file
from passlib.hash import pbkdf2_sha256
from flask_login import login_user, login_required, logout_user, current_user

from forms import LoginForm, RegisterForm
from config import app, db, ALLOWED_EXTENSIONS
from models.models import User
from werkzeug.utils import secure_filename
from utils import generate_password_hash
from flask import send_from_directory
import os


# START APP
@app.route('/')
def index():
    if 'id' in session:
        return redirect(url_for('board'))

    return render_template("index.html", title='Home')


# AUTH METHODS
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        if form.username.data == 'admin' and form.password.data == 'admin1234':
            users = User.query.all()
            return render_template('adminboard.html', users=users)
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if pbkdf2_sha256.verify(form.password.data, user.password):
                login_user(user, remember=True)
                session['id'] = user.id
                return redirect(url_for('board'))
        elif user is None:
            return render_template('login.html', error='Invalid data, try again or SignUp', form=form)

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session['id'] = new_user.id
        login_user(new_user, remember=False)
        return redirect(url_for('board'))
    return render_template('signup.html', form=form)


# file work

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/file_in_work', methods=['GET', 'POST'])
def file_in_work():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            os.system("python3 txttopdf.py " + app.config['UPLOAD_FOLDER'] + filename)
            return redirect(url_for('board'))

    return redirect(url_for('board'))


# @app.route('/uploads/<filename>')
# def uploaded_file(filename):
#     os.system("python3 txttopdf.py " + app.config['UPLOAD_FOLDER'] + filename)
#     return send_from_directory(app.config['UPLOAD_FOLDER'],
#                                filename)


@app.route('/return-files/')
def return_files():
    try:
        if 'id' in session:
            user_id = session['id']
            user = User.query.filter_by(id=user_id).first()
            if user.file_counter == None:
                user.file_counter = 1
            else:
                user.file_counter += 1
            db.session.commit()
        return send_file('/home/unatart/networks/course_proj/output.pdf', attachment_filename='output.pdf')
    except Exception as e:
        return str(e)


@app.route('/board')
@login_required
def board():
    return render_template('board.html', title='Board')


@app.route('/adminboard')
@login_required
def adminboard():
    return render_template('adminboard.html')


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
