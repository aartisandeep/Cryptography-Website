# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask import send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
import secrets
import os
from werkzeug.utils import secure_filename
from flask import send_file
import hashlib
from flask import Response
from flask import make_response
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
# from flask import Markup


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mykeysecret'
db = SQLAlchemy(app)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'IS5new', 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB limit

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CryptographicKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encryption_type = db.Column(db.String(10), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300))
    filepath = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    md5_hash = db.Column(db.String(32))
    #newly added:
    sha256_hash = db.Column(db.String(64))
    encrypted_filename = db.Column(db.String(300), nullable=True)

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('profile'))  #rredirect to user's profile or dashboard
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        existing_user = User.query.filter_by(email=email).first()
        if existing_user is None:
            password = request.form['password']
            user = User(email=email, name=name)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully, please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email already in use', 'danger')
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_password = request.form['new_password']
        user.set_password(new_password)
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys():
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    user_id = session['user_id']
    keys = []  # This will now hold tuples of (key, type)
    if request.method == 'POST':
        number_of_keys = int(request.form.get('number_of_keys', 1))
        encryption_type = request.form['encryption_type']  # "AES" or "DES"
        key_length = 16 if encryption_type == "AES" else 8  # 16 bytes for AES, 8 bytes for DES

        if number_of_keys < 1 or number_of_keys > 20:
            flash('Please enter a number between 1 and 20.', 'warning')
        else:
            for _ in range(number_of_keys):
                # Adjust key length based on encryption type
                new_key = secrets.token_hex(key_length)  # Generate key of appropriate length
                # Create a new CryptographicKey instance and add it to the database, including the encryption type
                db_key = CryptographicKey(key=new_key, user_id=user_id, encryption_type=encryption_type)
                db.session.add(db_key)
                keys.append((new_key, encryption_type))  # Save keys as tuples of (key, type) for display
            db.session.commit()

    # Adjust the rendering to pass keys as tuples of (key, type)
    return render_template('generate_keys.html', keys=keys)



@app.route('/my_keys')
def my_keys():
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_keys = CryptographicKey.query.filter_by(user_id=user_id).all()
    return render_template('my_keys.html', keys=user_keys)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Calculate the MD5 hash of the uploaded file
            file_md5 = calculate_md5(filepath)
            file_sha256 = calculate_sha256(filepath)

            # Save the file information and MD5 hash to the database
            new_file = File(
                filename=filename,
                filepath=filepath,
                md5_hash=file_md5,  # Store the hash
                sha256_hash=file_sha256,
                user_id=session['user_id']
            )
            db.session.add(new_file)
            db.session.commit()

            flash('File successfully uploaded', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid file type or no file selected', 'warning')

    return render_template('upload.html')



@app.route('/my_files')
def my_files():
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_files = File.query.filter_by(user_id=user_id).all()
    # return render_template('my_files.html', files=user_files)
    user_files = File.query.filter_by(user_id=user_id).all()
    user_keys = CryptographicKey.query.filter_by(user_id=user_id).all()
    return render_template('my_files.html', files=user_files, user_keys=user_keys)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    user_file = File.query.filter_by(filename=filename, user_id=session['user_id']).first()
    if user_file:
        # Define the full path to the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # Set the download attribute to prompt a file download
        return send_file(file_path, as_attachment=True)
    else:
        flash('File not found', 'warning')
        return redirect(url_for('my_files'))

@app.route('/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    # Retrieve the file from the database
    user_file = File.query.filter_by(id=file_id, user_id=session['user_id']).first()
    if user_file:
        # Delete the file from the filesystem
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user_file.filename))
        except OSError as e:
            flash('Error deleting file', 'warning')
            app.logger.error(f"Error deleting file: {e}")
            return redirect(url_for('my_files'))

        # Delete the file from the database
        db.session.delete(user_file)
        db.session.commit()
        flash('File successfully deleted', 'success')
    else:
        flash('File not found', 'warning')

    return redirect(url_for('my_files'))

@app.route('/encrypt_file/<int:file_id>', methods=['POST'])
def encrypt_file(file_id):
    print(f"Encrypt file route called for file ID: {file_id}")  # Debug print

    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    user_file = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()
    key_id = request.form['key_id']
    user_key = CryptographicKey.query.filter_by(id=key_id, user_id=session['user_id']).first()

    if user_key is None:
        flash('Invalid key', 'warning')
        return redirect(url_for('my_files'))

    # Define the full path to the file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_file.filename)
    print(f"File path: {file_path}")  # Debug print

    # Read the file content
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Encrypt the file data using DES
    try:
        des = DES.new(bytes.fromhex(user_key.key), DES.MODE_ECB)  # Convert the hex key to bytes
        padded_data = pad(file_data, DES.block_size)  # Pad the data to be a multiple of the block size
        encrypted_data = des.encrypt(padded_data)
        print("Encryption successful")  # Debug print
    except ValueError as e:
        flash(f'Encryption error: {e}', 'error')
        print(f"Encryption failed: {e}")  # Debug print
        return redirect(url_for('my_files'))

    # Generate a unique encrypted file name
    encrypted_filename = secure_filename(f"{user_file.filename}-{secrets.token_hex(4)}.enc")
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

    # Write the encrypted data back to a new file
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
        print(f"Encrypted file written to {encrypted_file_path}")  # Debug print

    # Save the encrypted file name in the database
    user_file.encrypted_filename = encrypted_filename
    db.session.commit()
    print(f"Encrypted file name '{encrypted_filename}' saved to database for file ID {file_id}")  # Debug print

    flash('File encrypted successfully', 'success')
    return redirect(url_for('my_files'))


#download encrupted file
@app.route('/download_file/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    # Make sure the filename is secure
    filename = secure_filename(filename)

    # Define the full path to the encrypted file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists
    if os.path.exists(file_path) and os.path.isfile(file_path):
        # Send the file for download
        return send_file(file_path, as_attachment=True)
    else:
        flash('File not found.', 'warning')
        return redirect(url_for('my_files'))

from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

@app.route('/decrypt_file/<int:file_id>', methods=['POST'])
def decrypt_file(file_id):
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    user_file = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()
    key_id = request.form['key_id']
    user_key = CryptographicKey.query.filter_by(id=key_id, user_id=session['user_id']).first()

    if user_key is None or not user_file.encrypted_filename:
        flash('Invalid key or file is not encrypted', 'warning')
        return redirect(url_for('my_files'))

    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_file.encrypted_filename)

    # Read the encrypted file content
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    try:
        des = DES.new(bytes.fromhex(user_key.key), DES.MODE_ECB)
        decrypted_data = unpad(des.decrypt(encrypted_data), DES.block_size)
    except ValueError as e:
        flash(f'Decryption error: {e}', 'error')
        return redirect(url_for('my_files'))

    # Save the decrypted data back to a file (or handle as needed)
    decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypted_{user_file.filename}")
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    flash('File decrypted successfully', 'success')
    return redirect(url_for('download_file', filename=f"decrypted_{user_file.filename}"))


#download md5 hash fiule
@app.route('/download_hash/<int:file_id>')
def download_hash(file_id):
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    # Retrieve the file from the database
    user_file = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()

    # Create a response with the MD5 hash as a downloadable file
    response = make_response(user_file.md5_hash)
    response.headers["Content-Disposition"] = f"attachment; filename={user_file.filename}-hash.txt"
    response.headers["Content-Type"] = "text/plain"
    return response

#sha256 hash route:
@app.route('/download_sha256_hash/<int:file_id>')
def download_sha256_hash(file_id):
    if 'user_id' not in session:
        flash('You need to login first', 'info')
        return redirect(url_for('login'))

    # Retrieve the file from the database
    user_file = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()

    # Create a response with the SHA256 hash as a downloadable file
    response = make_response(user_file.sha256_hash)
    response.headers["Content-Disposition"] = f"attachment; filename={user_file.filename}-sha256-hash.txt"
    response.headers["Content-Type"] = "text/plain"
    return response


@app.route('/change_password', methods=['POST'])
def change_password():
    user = User.query.get(session['user_id'])
    new_password = request.form['new_password']
    user.set_password(new_password)
    db.session.commit()
    flash('Your password has been updated.', 'success')
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    user = User.query.get(session['user_id'])
    db.session.delete(user)
    db.session.commit()
    session.pop('user_id', None)
    flash('Your account has been deleted.', 'success')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have successfully logged out.', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)