from flask import Flask
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

CSRF_ENABLED = True
SECRET_KEY = 'you-will-never-guess'

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/unatart/networks/course_proj/backenddb/backend.sqlite'
app.config.from_object('config')

UPLOAD_FOLDER = '/home/unatart/networks/course_proj/backenddb/'
ALLOWED_EXTENSIONS = 'txt'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
