from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.debug = True #lets you run files on localhost without resetting sever

#config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'elleinin'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' #overrides default tuple with dict

#init
mysql = MySQL(app)

Articles = Articles()

#set route
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/articles')
def articles():
    return render_template('articles.html', articles = Articles)

@app.route('/article/<string:id>/')
def article(id):
    return render_template('article.html', id=id)

#create WTForm
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match'),
        validators.Length(min=6, max=50)
    ])
    confirm = PasswordField('Confirm Password')

#Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        #create cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
        #commit to DB
        mysql.connection.commit()
        #close connection
        cur.close()
        flash('Thank you for registering!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
        if request.method == 'POST':
            username = request.form['username']
            password_candidate = request.form['password']

            #create cursor
            cur = mysql.connection.cursor()

            #get user by username
            result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

            if result > 0:
                #get hash
                data = cur.fetchone() #looks at query and fetches data. only fetches one
                password = data['password']

                #compare passwords
                if sha256_crypt.verify(password_candidate, password):
                    app.logger.info('PASSWORD MATCHED')
                    session['logged_in'] = True
                    session['username'] = username
                    flash('Successfully logged in', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'Invalid login'
                    app.logger.info('INCORRECT USERNAME OR PASSWORD')
                    return render_template('login.html', error=error)
                #close connection
                cur.close()

            else:
                error = 'Username not found'
                return render_template('login.html', error=error)
        return render_template('login.html')

#check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized. Please log in your account to view your profile.', 'danger')
            return redirect(url_for('login'))
    return wrap

#logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))
#successful login dashboard
@app.route('/dashboard')
@is_logged_in #checks if user is logged in; only shows dashboard when logged in
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.secret_key='password1234'
    app.run()
    # allows application to start