from flask import Flask, flash, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf import CSRFProtect

import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # Elak akses cookie melalui JavaScript
    SESSION_COOKIE_SECURE=True,       # Hanya hantar cookie melalui HTTPS (guna bila dah deploy)
    SESSION_COOKIE_SAMESITE='Lax'     # Cegah CSRF rentas laman (boleh juga guna 'Strict')
)


csrf = CSRFProtect(app)

DATABASE = 'members.db'

# Securely hashed user passwords
USERS = {
    "staff": {"password": generate_password_hash("staffpass"), "role": "staff"},
    "member": {"password": generate_password_hash("memberpass"), "role": "member"},
    "pakkarim": {"password": generate_password_hash("karim"), "role": "staff"}
}

# RBAC decorator for staff-only routes
def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session.get('role') != 'staff':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# DB helper functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                 )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                 )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                 )''')
    db.commit()

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = USERS.get(username)
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Invalid username or password.", 'danger')  # Menggunakan category 'danger' untuk alert
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()

    # Kira jumlah semua ahli
    total_members = query_db("SELECT COUNT(*) FROM members", one=True)[0]

    # Kira ahli yang status 'active' (case-insensitive)
    active_members = query_db("SELECT COUNT(*) FROM members WHERE LOWER(membership_status) = 'active'", one=True)[0]

    # Kira jumlah kelas
    total_classes = query_db("SELECT COUNT(*) FROM classes", one=True)[0]

    return render_template('dashboard.html',
                           username=session['user'],
                           total_members=total_members,
                           active_members=active_members,
                           total_classes=total_classes)


# Add member
@app.route('/add_member', methods=['GET', 'POST'])
@staff_required
def add_member():
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        if not name.strip() or status not in ["active", "inactive"]:
            return "Invalid input!"

        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

# View specific member's classes
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                       "JOIN member_classes mc ON c.id = mc.class_id "
                       "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)

# Register a member to a class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
@staff_required
def register_class(member_id):
    classes = query_db("SELECT * FROM classes")

    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))

    return render_template('register_class.html', member_id=member_id, classes=classes)

# View all members
@app.route('/view_members')
@staff_required
def view_members():
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# Register a new member
@app.route('/register_member', methods=['GET', 'POST'])
@staff_required
def register_member():
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        if not name.strip() or status not in ["active", "inactive"]:
            return "Invalid input!"

        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))

    return render_template('register_member.html')

# Add new class
@app.route('/add_class', methods=['GET', 'POST'])
@staff_required
def add_class():
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        if not class_name.strip() or not class_time.strip():
            return "Invalid input!"

        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))

    return render_template('add_class.html')

# View all classes
@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Delete a member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
@staff_required
def delete_member(member_id):
    db = get_db()
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    db.commit()
    return redirect(url_for('view_members'))

# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)