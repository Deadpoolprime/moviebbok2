from flask import Flask, render_template, request, redirect, url_for, abort, flash, session
import mysql.connector, random, string
import os
from werkzeug.utils import secure_filename
# Import password hashing utilities
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

UPLOAD_FOLDER = 'static/posters'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# MySQL connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="movie_booking"
)
cursor = db.cursor(dictionary=True)
app.secret_key = "supersecretkey"  # Required for session management
ADMIN_PASSWORD = "admin123"  # simple admin password

# Admin login check (super simple)
def check_admin(password):
    if password != ADMIN_PASSWORD:
        abort(401)  # Unauthorized

# NEW: User Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                       (username, email, password_hash))
        db.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# NEW: User Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

# NEW: User Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# NEW: User's Bookings Page
@app.route('/my_bookings')
def my_bookings():
    if 'user_id' not in session:
        flash('You must be logged in to view your bookings.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor.execute("""
      SELECT 
        b.ticket_id, 
        m.title, 
        s.seat_no,
        st.show_time
      FROM bookings b
      JOIN users u ON b.user_id = u.id
      JOIN seats s ON b.seat_id = s.id
      JOIN showtimes st ON s.showtime_id = st.id
      JOIN movies m ON st.movie_id = m.id
      WHERE u.id = %s
      ORDER BY st.show_time DESC
    """, (user_id,))
    bookings = cursor.fetchall()
    return render_template('my_bookings.html', bookings=bookings)

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template("admin_dashboard.html")

def generate_ticket_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

# MODIFIED: admin_bookings query to join with users table
@app.route('/admin/bookings')
def admin_bookings():
    password = request.args.get("password")
    check_admin(password)
    cursor.execute("""
      SELECT 
        b.ticket_id, u.username, u.email, 
        m.title, 
        s.seat_no,
        st.show_time
      FROM bookings b
      JOIN users u ON b.user_id = u.id
      JOIN seats s ON b.seat_id = s.id
      JOIN showtimes st ON s.showtime_id = st.id
      JOIN movies m ON st.movie_id = m.id
    """)
    bookings = cursor.fetchall()
    return render_template("admin_bookings.html", bookings=bookings)

@app.route('/admin/add_movie', methods=["GET", "POST"])
def add_movie():
  password = request.args.get("password")
  check_admin(password)

  poster_url = None

  if request.method == "POST":
    title = request.form["title"]

    if 'poster' in request.files:
      file = request.files['poster']
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        poster_url = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')

    cursor.execute("INSERT INTO movies (title, poster_url) VALUES (%s, %s)", (title, poster_url))
    db.commit()

    flash(f"Movie '{title}' added successfully! Now add showtimes.")
    return redirect(f"/admin/add_movie?password=admin123")

  return render_template("add_movie.html")

@app.route('/admin/edit_movie', methods=["GET"])
def admin_edit_movie_list():
  password = request.args.get("password")
  check_admin(password)

  cursor.execute("SELECT id, title, poster_url FROM movies ORDER BY title")
  movies = cursor.fetchall()

  return render_template("admin_edit_movie_list.html", movies=movies)

@app.route('/admin/edit_movie/<int:movie_id>', methods=["GET", "POST"])
def admin_edit_movie(movie_id):
  password = request.args.get("password")
  check_admin(password)

  cursor.execute("SELECT id, title, poster_url FROM movies WHERE id = %s", (movie_id,))
  movie = cursor.fetchone()
  if not movie:
    abort(404)

  if request.method == "POST":
    new_title = request.form["title"]
    current_poster_url = movie['poster_url']

    if 'poster' in request.files:
      file = request.files['poster']
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        current_poster_url = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')

    cursor.execute("UPDATE movies SET title = %s, poster_url = %s WHERE id = %s", 
                   (new_title, current_poster_url, movie_id))
    db.commit()

    flash(f"Movie '{new_title}' updated successfully!")
    return redirect(f"/admin/edit_movie?password=admin123")

  return render_template("admin_edit_movie.html", movie=movie)

@app.route('/admin/add_showtime', methods=["GET", "POST"])
def admin_add_showtime():
  password = request.args.get("password")
  check_admin(password)

  cursor.execute("SELECT id, title FROM movies")
  movies = cursor.fetchall()

  if request.method == "POST":
    movie_id = request.form["movie_id"]
    show_date = request.form["show_date"] 
    time_only = request.form["show_time_only"] 

    show_time = f"{show_date} {time_only}:00"

    cursor.execute("INSERT INTO showtimes (movie_id, show_time) VALUES (%s, %s)", (movie_id, show_time))
    db.commit()
    showtime_id = cursor.lastrowid

    for n in range(25):
      seat_no = chr(65 + n // 5) + str(n % 5 + 1)
      cursor.execute("INSERT INTO seats (showtime_id, seat_no) VALUES (%s,%s)", (showtime_id, seat_no))
    db.commit()

    flash(f"Showtime '{show_time}' added successfully!")
    return redirect(f"/admin/add_showtime?password=admin123")

  return render_template("admin_add_showtime.html", movies=movies)

@app.route('/admin/remove_showtime', methods=["GET", "POST"])
def admin_remove_showtime():
  password = request.args.get("password")
  check_admin(password)

  if request.method == "POST":
    showtime_id = request.form.get("showtime_id")
    # Deletion order matters due to foreign keys. Bookings depend on showtime_id
    cursor.execute("DELETE FROM bookings WHERE showtime_id = %s", (showtime_id,))
    cursor.execute("DELETE FROM seats WHERE showtime_id = %s", (showtime_id,))
    cursor.execute("DELETE FROM showtimes WHERE id = %s", (showtime_id,))
    db.commit()
    flash("Showtime and all associated bookings/seats removed successfully!", 'success')
    return redirect(f"/admin/remove_showtime?password=admin123")

  cursor.execute("""
    SELECT st.id, st.show_time, m.title
    FROM showtimes st
    JOIN movies m ON st.movie_id = m.id
    ORDER BY m.title, st.show_time
  """)
  showtimes = cursor.fetchall()
  return render_template("admin_remove_showtime.html", showtimes=showtimes)

# ### THIS IS THE CORRECTED FUNCTION ###
@app.route('/admin/remove_movie', methods=["GET", "POST"])
def admin_remove_movie():
    password = request.args.get("password")
    check_admin(password)

    if request.method == "POST":
        movie_id = request.form.get("movie_id")

        # Fetch showtime IDs associated with the movie
        cursor.execute("SELECT id FROM showtimes WHERE movie_id = %s", (movie_id,))
        showtime_ids = [row['id'] for row in cursor.fetchall()]

        if showtime_ids:
            placeholders = ','.join(['%s'] * len(showtime_ids))

            cursor.execute(f"DELETE FROM bookings WHERE showtime_id IN ({placeholders})", tuple(showtime_ids))
            cursor.execute(f"DELETE FROM seats WHERE showtime_id IN ({placeholders})", tuple(showtime_ids))
            cursor.execute("DELETE FROM showtimes WHERE movie_id = %s", (movie_id,))

        cursor.execute("DELETE FROM movies WHERE id = %s", (movie_id,))
        db.commit()
        flash("Movie, all showtimes, bookings, and seats removed successfully!", 'success')
        return redirect(f"/admin/remove_movie?password=admin123")

    cursor.execute("SELECT id, title FROM movies ORDER BY title")
    movies = cursor.fetchall()
    return render_template("admin_remove_movie.html", movies=movies)
