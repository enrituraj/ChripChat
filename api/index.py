from flask import Flask,render_template,redirect,jsonify,url_for,request,flash,session,send_file,abort
from functools import wraps
# Form Validation
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

#connecting to mongodb atlas
import pymongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
# for image upload using gridfs
from bson import ObjectId
from gridfs import GridFS
from io import BytesIO
#enviroment variable setup
from dotenv import load_dotenv, find_dotenv
import os
# Locate the .env file outside of the api directory
# dotenv_path = find_dotenv(raise_error_if_not_found=True)
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)
# Access environment variables
secret_key = os.getenv('SECRET_KEY')
mongo_uri = os.getenv('MONGO_URI')

app = Flask(__name__)
app.secret_key = secret_key

uri = mongo_uri
# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("You successfully connected to MongoDB!")
except Exception as e:
    print(e)

#database initialization
db = client.chripchat
# use a collection named "users"
users = db["user"]

@app.route('/')
def home():    
    user = session.get('user')
    if user:
        return render_template('index.html', user=user)  
    else:
        return render_template('index.html')
        




# generate uuid for unique identification of user
def generate_unique_id():
    return secrets.token_hex(4)[:8]

# validate name
def is_valid_name(name):
    return len(name) >= 3

#validate email
def is_valid_email(email):
    # Regular expression for a simple email validation
    email_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
    return bool(re.match(email_pattern, email))

#validate password
def is_valid_password(password):
    password_pattern = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    return bool(re.match(password_pattern, password))



@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        chrip_id = request.form.get('chripid')
        password = request.form.get('password')

        # validating the user input
        if not name or not chrip_id or not password:
            flash('All fields must be filled out.', 'error')
        elif not is_valid_name(name):
            flash('Please enter a valid name.', 'error')
        elif not is_valid_password(password):
            flash('Please enter a strong password.', 'error')
        else:
            #checking if chrip_id exists or not
            existing_chrip_id = users.find_one({'chrip_id': chrip_id})
            if existing_chrip_id:
                flash('chrip_id already taken. Please try another.', 'error')
            else:
                #hashing password
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                #genrating unique_hash
                unique_id = generate_unique_id()
                # Get the current time
                current_time = datetime.utcnow()

                user_data = {
                    'uuid':unique_id,
                    'name': name,
                    'chrip_id': chrip_id,
                    'role':'user',
                    'password':hashed_password,
                    'text_password':password, # removed before going to live
                    'created_At':current_time
                }

                users.insert_one(user_data)
                flash('Signup successful! Please login.', 'success')
                return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        chrip_id = request.form.get('chripid')
        password = request.form.get('password')
        if not chrip_id or not password:
            flash('All fields must be filled out.', 'error')
        elif not is_valid_password(password):
            flash('Please enter a strong password.', 'error')
        else:
            #finding user with that email
            user = users.find_one({'chrip_id': chrip_id})
            if user and check_password_hash(user['password'], password):
                if user['role'] == 'admin':
                    session['admin'] = {'uuid': user['uuid'], 'name': user['name'], 'chrip_id': user['chrip_id'],'role':user['role']}
                    return redirect(url_for('admin_dashboard'))                    
                else:
                    session['user'] = {'uuid': user['uuid'], 'name': user['name'], 'chrip_id': user['chrip_id'],'role':user['role']}
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
            else:
                flash('Invalid email or password. Please try again.', 'error')
    return render_template('login.html')
    
@app.route('/logout')
def logout():
    user = session.get('user')
    if user:
        session.pop('user', None)
    else:
        session.pop('admin', None)
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def admin_dashboard():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)