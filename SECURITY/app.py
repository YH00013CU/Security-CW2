from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Use SQLite for simplicity
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Create the database tables before running the app
with app.app_context():
    db.create_all()

# Password security criteria
PASSWORD_MIN_LENGTH = 8

def is_valid_password(password):
    if len(password) < PASSWORD_MIN_LENGTH:
        return False

    # Check for at least one uppercase letter and one digit
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)

    return has_uppercase and has_digit

@app.route('/')
def root():
    # Redirect to the login page
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Specific "doctor" credentials for demonstration
        doctor_username = 'doctor'
        doctor_password = 'Doctor1234'  # Example password, you should use a secure one

        # Check if the provided credentials match the "doctor" credentials
        if username == doctor_username and password == doctor_password:
            # Successful login with doctor credentials
            return redirect(url_for('doctor'))

        # Query the database to check if the user exists
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # Successful login for regular users
            return redirect(url_for('home'))
        else:
            # Failed login
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/doctor')
def doctor():
    # Access level check for the "doctor" page
    if 'username' in request.cookies and request.cookies['username'] == 'doctor':
        return render_template('doctor.html')
    else:
        return render_template('doctor.html')

@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    if request.method == 'POST':
        # Process form data if needed
        pass

    return render_template('schedule.html')
# Update the route for Patients Information
@app.route('/patients_information')
def patients_information():
    return render_template('patients_information.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username is already registered
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('signup.html', error='Username already registered. Please choose a different one.')

        # Validate the password
        if is_valid_password(password):
            # Hash the password before storing it in the database
            hashed_password = generate_password_hash(password, method='sha256')

            # Create a new user and add it to the database
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))
        else:
            return render_template('signup.html', error='Weak password. It must be at least 8 characters long with at least 1 uppercase letter and 1 number.')

    return render_template('signup.html')


if __name__ == '__main__':
    app.run(debug=True)
