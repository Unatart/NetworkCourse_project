from flask import Flask, render_template
app = Flask(__name__)


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/signin.html")
def login():
    return render_template('signin.html')


@app.route("/register.html")
def register():
    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True)