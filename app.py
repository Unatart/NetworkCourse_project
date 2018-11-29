from routes.routes import *
from werkzeug.contrib.fixers import ProxyFix


app.wsgi_app = ProxyFix(app.wsgi_app)
if __name__ == '__main__':
    app.run(port=3002)
