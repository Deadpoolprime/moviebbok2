from flask import Flask, render_template, request, redirect, url_for, abort, flash, session
import random, string
import os
from werkzeug.utils import secure_filename
# Import password hashing utilities
from werkzeug.security import generate_password_hash, check_password_hash

# PostgreSQL Imports
import psycopg2
from psycopg2.extras import DictCursor
from urllib.parse import urlparse

app = Flask(__name__)

UPLOAD_FOLDER = 'static/posters'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- PostgreSQL Connection Setup ---
# When deployed on Render, the DATABASE_URL environment variable is automatically set.
# Locally, you can set this variable or replace the default 'your_local_postgres_url'
# with a valid local connection string for testing.
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost:5432/movie_booking')

def get_db_connection():
    """Establishes connection to PostgreSQL using the DATABASE_URL environment variable."""
    try:
        # Parse the connection string
        result = urlparse(DATABASE_URL)
        username = result.username
        password = result.password
        database = result.path[1:]
        hostname = result.hostname

        conn = psycopg2.connect(
            database=database,
            user=username,
            password=password,
            host=hostname
        )
        # Use DictCursor to ensure data comes back as dictionaries, 
        # maintaining compatibility with the rest of the application.
        cursor = conn.cursor(cursor_factory=DictCursor)
        return conn, cursor
    except Exception as e:
        print(f"Database connection error: {e}")
        # Aborting startup if DB connection fails
        raise ConnectionError(f"Failed to connect to database: {e}")

# Establish connection globally (Note: In a large production app, 
# pooling or per-request connection management might be preferred, 
# but this mirrors the simplicity of the original MySQL setup.)
db, cursor = get_db_connection()

# Required for session management
app.secret_key = os.environ.get("SECRET_KEY", "fallback_supersecretkey_change_me")
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

        # Re-establish cursor (good practice)
        db, cursor = get_db_connection()

        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
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
        
        db, cursor = get_db_connection()

        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
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
    db, cursor = get_db_connection()

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

@app.route('/admin/bookings')
def admin_bookings():
    password = request.args.get("password")
    check_admin(password)
    db, cursor = get_db_connection()

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
    db, cursor = get_db_connection()
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
    db, cursor = get_db_connection()
    cursor.execute("SELECT id, title, poster_url FROM movies ORDER BY title")
    movies = cursor.fetchall()
    return render_template("admin_edit_movie_list.html", movies=movies)

@app.route('/admin/edit_movie/<int:movie_id>', methods=["GET", "POST"])
def admin_edit_movie(movie_id):
    password = request.args.get("password")
    check_admin(password)
    db, cursor = get_db_connection()
    
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
    db, cursor = get_db_connection()

    cursor.execute("SELECT id, title FROM movies")
    movies = cursor.fetchall()
    
    if request.method == "POST":
        movie_id = request.form["movie_id"]
        show_date = request.form["show_date"] 
        time_only = request.form["show_time_only"] 
        show_time = f"{show_date} {time_only}:00"
        
        # --- IMPORTANT POSTGRES CHANGE ---
        # PostgreSQL/psycopg2 requires using RETURNING id instead of cursor.lastrowid
        cursor.execute("INSERT INTO showtimes (movie_id, show_time) VALUES (%s, %s) RETURNING id", 
                       (movie_id, show_time))
        showtime_id = cursor.fetchone()['id']
        
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
    db, cursor = get_db_connection()

    if request.method == "POST":
        showtime_id = request.form.get("showtime_id")
        
        # Note: CASCADE ON DELETE in the schema is usually better, but manually deleting here:
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

@app.route('/admin/remove_movie', methods=["GET", "POST"])
def admin_remove_movie():
    password = request.args.get("password")
    check_admin(password)
    db, cursor = get_db_connection()

    if request.method == "POST":
        movie_id = request.form.get("movie_id")
        
        # Get all showtime IDs related to the movie
        cursor.execute("SELECT id FROM showtimes WHERE movie_id = %s", (movie_id,))
        showtime_ids = [row['id'] for row in cursor.fetchall()]
        
        if showtime_ids:
            # PostgreSQL requires parameter substitution for IN clauses
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

@app.route('/admin/stats')
def admin_stats():
    password = request.args.get("password")
    check_admin(password)
    db, cursor = get_db_connection()

    cursor.execute("SELECT COUNT(id) AS total_bookings FROM bookings")
    total_bookings = cursor.fetchone()['total_bookings']
    
    cursor.execute("SELECT COUNT(id) AS total_movies FROM movies")
    total_movies = cursor.fetchone()['total_movies']
    
    cursor.execute("""
        SELECT m.title, st.show_time, COUNT(b.id) AS booking_count
        FROM bookings b
        JOIN showtimes st ON b.showtime_id = st.id
        JOIN movies m ON st.movie_id = m.id
        GROUP BY st.id, st.show_time, m.title
        ORDER BY booking_count DESC
        LIMIT 5
    """)
    top_showtimes = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(id) AS total_seats FROM seats")
    total_seats = cursor.fetchone()['total_seats']
    
    cursor.execute("SELECT COUNT(id) AS booked_seats FROM seats WHERE is_booked = TRUE")
    booked_seats = cursor.fetchone()['booked_seats']
    
    unbooked_seats = total_seats - booked_seats
    
    stats = {
        'total_bookings': total_bookings,
        'total_movies': total_movies,
        'unbooked_seats': unbooked_seats,
        'top_showtimes': top_showtimes
    }
    return render_template("admin_stats.html", stats=stats)

@app.route('/', methods=["GET", "POST"])
def home():
    db, cursor = get_db_connection()
    if request.method == "POST" and "admin_password" in request.form:
        password = request.form["admin_password"]
        if password == ADMIN_PASSWORD:
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Incorrect admin password!", 'error')
            return redirect(url_for("home"))
            
    cursor.execute("SELECT * FROM movies")
    movies = cursor.fetchall()
    return render_template("index.html", movies=movies)

@app.route('/timings/<int:movie_id>')
def show_timings(movie_id):
    db, cursor = get_db_connection()
    cursor.execute("SELECT title FROM movies WHERE id=%s", (movie_id,))
    movie = cursor.fetchone()
    if not movie:
        abort(404)
        
    cursor.execute("SELECT id, show_time FROM showtimes WHERE movie_id=%s ORDER BY show_time", (movie_id,))
    showtimes = cursor.fetchall()
    return render_template("timings.html", movie=movie, showtimes=showtimes)

@app.route('/seats/<int:showtime_id>')
def seats(showtime_id):
    db, cursor = get_db_connection()
    cursor.execute("""
        SELECT st.id, st.show_time, m.title 
        FROM showtimes st
        JOIN movies m ON st.movie_id = m.id
        WHERE st.id=%s
    """, (showtime_id,))
    showtime_data = cursor.fetchone()
    
    if not showtime_data:
        abort(404)
        
    cursor.execute("SELECT * FROM seats WHERE showtime_id=%s ORDER BY seat_no", (showtime_id,))
    seats_data = cursor.fetchall()
    
    return render_template("seats.html", showtime=showtime_data, seats=seats_data)

@app.route('/book/<int:showtime_id>/<int:seat_id>', methods=["GET", "POST"])
def book(showtime_id, seat_id):
    if 'user_id' not in session:
        flash('Please log in to book a seat.', 'warning')
        return redirect(url_for('login'))
        
    db, cursor = get_db_connection()
    
    cursor.execute("SELECT * FROM seats WHERE id=%s AND showtime_id=%s", (seat_id, showtime_id))
    seat = cursor.fetchone()
    
    if not seat:
        abort(404)
        
    if seat["is_booked"]:
        flash("Sorry, this seat has just been booked by someone else.", 'error')
        return redirect(url_for('seats', showtime_id=showtime_id))
        
    cursor.execute("""
        SELECT st.id AS showtime_id, st.show_time, m.title, m.id AS movie_id
        FROM showtimes st
        JOIN movies m ON st.movie_id = m.id
        WHERE st.id=%s
    """, (showtime_id,))
    showtime_data = cursor.fetchone()
    
    if request.method == "POST":
        user_id = session['user_id']
        ticket_id = generate_ticket_id()
        
        # Check availability again inside POST request to prevent race condition
        cursor.execute("SELECT is_booked FROM seats WHERE id=%s FOR UPDATE", (seat_id,))
        if cursor.fetchone()['is_booked']:
            flash("Sorry, this seat was just booked.", 'error')
            return redirect(url_for('seats', showtime_id=showtime_id))

        cursor.execute("UPDATE seats SET is_booked=TRUE WHERE id=%s", (seat_id,))
        cursor.execute("INSERT INTO bookings (ticket_id, user_id, showtime_id, seat_id) VALUES (%s,%s,%s,%s)",
                       (ticket_id, user_id, showtime_id, seat_id))
        db.commit()
        
        return redirect(url_for("ticket", ticket_id=ticket_id))
        
    return render_template("book.html", movie=showtime_data, seat=seat)

@app.route('/ticket/<ticket_id>')
def ticket(ticket_id):
    db, cursor = get_db_connection()
    cursor.execute("""
         SELECT 
          b.ticket_id, u.username, u.email, 
          m.title, 
          s.seat_no,
          st.show_time
         FROM bookings b
         JOIN users u ON b.user_id = u.id
         JOIN seats s ON b.seat_id=s.id
         JOIN showtimes st ON s.showtime_id=st.id
         JOIN movies m ON st.movie_id=m.id
         WHERE b.ticket_id=%s
         """, (ticket_id,))
    booking = cursor.fetchone()
    
    if not booking:
        abort(404)
        
    return render_template("ticket.html", booking=booking)

if __name__ == "__main__":
    # If running locally, set a fake DATABASE_URL for testing
    if 'DATABASE_URL' not in os.environ:
        print("WARNING: DATABASE_URL not set. Using local default.")
        # Replace this with your actual local PostgreSQL connection string
        os.environ['DATABASE_URL'] = 'postgresql://user:password@localhost:5432/movie_booking'
        
    app.run(debug=True)