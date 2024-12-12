from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import subprocess
import threading

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key for security purposes

login_manager = LoginManager()
login_manager.init_app(app)

# Sample user data (You should replace this with a database)
users = {'driver': 'password123'}  # username: password

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        user = User()
        user.id = user_id  # user_id corresponds to the username in this case
        return user
    return None

@app.route('/')
def home():
    return render_template('index1.html')  # Ensure you have an index1.html file

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            user = User()
            user.id = username
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')  # Ensure you have a login.html file

@app.route('/dashboard')
@login_required
def dashboard():
    is_traveling = session.get('is_traveling', False)  # Get travel state from session
    return render_template('dashboard.html', is_traveling=is_traveling)  # Ensure you have a dashboard.html file

# Store the process globally to manage the subprocess
process = None
process_lock = threading.Lock()

# Function to start the driver monitoring system
def start_detection():
    global process
    with process_lock:
        try:
            process = subprocess.Popen(['python', r"C:\Users\narai\OneDrive\Desktop\cour\prog.py"]) 
            process.wait()  # Wait for the process to complete
        except Exception as e:
            print(f"Error occurred: {e}")

# Toggle travel function (Start/Stop driver monitoring system)
@app.route('/toggle_travel', methods=['POST'])
@login_required  # Ensures only logged-in users can start/stop travel
def toggle_travel():
    global process
    is_traveling = session.get('is_traveling', False)

    with process_lock:
        if is_traveling:
            # If the user is currently traveling, stop the monitoring system
            session['is_traveling'] = False
            if process and process.poll() is None:
                process.terminate()  # Terminate the process
                process = None  # Reset process variable
                flash('Driver monitoring system stopped!')
            else:
                flash('No monitoring process running.')
        else:
            # If the user is not currently traveling, start the monitoring system
            session['is_traveling'] = True
            threading.Thread(target=start_detection).start()  # Start detection in a new thread
            flash('Driver monitoring system started!')

    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
