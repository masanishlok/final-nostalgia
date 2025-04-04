import os
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import json
from datetime import datetime
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from functools import wraps
import time
import requests
import logging
from bson.objectid import ObjectId
from flask_mail import Mail, Message
from dotenv import load_dotenv
# from forms import RegistrationForm


# Load environment variables from .env file
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "../templates")
STATIC_DIR = os.path.join(BASE_DIR, "../static")

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = os.getenv("SECRET_KEY", "y10ed69eda17e5b1d30fe4f53ca069bd6")

# Email configuration from .env
# Load environment variables
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "c12314870c1d2d45ab1d64e4dd9f735e")
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "dialusers@gmail.com")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "your_app_password")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "dialusers@gmail.com")

mail = Mail(app)
mail.init_app(app)

@app.route("/send_mail")
def send_mail():
    msg = Message("Hello", recipients=["dialusers@gmail.com"])
    msg.body = "This is a test email"
    mail.send(msg, asynchronous=True)  # Async email sending
    return "Email Sent!"

# API Keys from .env
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")
NEWS_API_KEY = os.getenv("NEWS_API_KEY")
LASTFM_API_KEY = os.getenv("LAST_FM_API_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

# MongoDB connection from .env
try:
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/nostalgia_db")
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client.nostalgia_db
    logger.info("Connected to MongoDB successfully")
except ConnectionFailure as e:
    logger.error(f"Could not connect to MongoDB: {e}")
    db = None

# Session Configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(BASE_DIR, 'sessions')
app.config['SESSION_PERMANENT'] = False
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
try:
    os.chmod(app.config['SESSION_FILE_DIR'], 0o700)
except Exception as e:
    logger.error(f"Error setting session directory permissions: {e}")
Session(app)

RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW = 60
user_requests = {}

WAYBACK_API_URL = "http://web.archive.org/cdx/search/cdx"

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Not logged in"}), 401
        user_id = session["user_id"]
        current_time = time.time()

        if user_id in user_requests:
            user_requests[user_id] = [t for t in user_requests[user_id] if current_time - t < RATE_LIMIT_WINDOW]
        else:
            user_requests[user_id] = []

        if len(user_requests[user_id]) >= RATE_LIMIT_REQUESTS:
            return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

        user_requests[user_id].append(current_time)
        return f(*args, **kwargs)
    return decorated_function

def scrape_page(url):
    try:
        with urlopen(url, timeout=10) as response:
            soup = BeautifulSoup(response.read(), 'html.parser')
            return soup
    except (HTTPError, URLError) as e:
        logger.error(f"Error scraping {url}: {e}")
        return None

# Retry decorator for API calls
def retry_on_failure(max_attempts=3, delay=2):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            attempts = 0
            last_error = None
            while attempts < max_attempts:
                try:
                    return f(*args, **kwargs)
                except requests.exceptions.RequestException as e:
                    attempts += 1
                    last_error = e
                    logger.error(f"{f.__name__} failed (attempt {attempts}/{max_attempts}): {e}")
                    if attempts == max_attempts:
                        logger.error(f"{f.__name__} failed after {max_attempts} attempts: {last_error}")
                        return None
                    time.sleep(delay)
                    logger.info(f"Retrying {f.__name__} (attempt {attempts + 1}/{max_attempts})")
                except Exception as e:
                    logger.error(f"Unexpected error in {f.__name__}: {e}")
                    return None
            return None
        return wrapper
    return decorator

def verify_recaptcha(recaptcha_response):
    """
    Verify the Google reCAPTCHA response with Google's API.
    """
    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {
        "secret": RECAPTCHA_SECRET_KEY,
        "response": recaptcha_response
    }
    response = requests.post(url, data=data)
    result = response.json()
    
    return result.get("success", False)

# ------------------------- Routes -------------------------

@app.route("/")
def home():
    return render_template("index.html", home_url=url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        recaptcha_response = request.form.get("g-recaptcha-response")

        # Validate reCAPTCHA
        if not verify_recaptcha(recaptcha_response):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            return render_template('login.html', home_url=url_for('home'), recaptcha_site_key=RECAPTCHA_SITE_KEY)

        # Check email and password
        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template('login.html', home_url=url_for('home'), recaptcha_site_key=RECAPTCHA_SITE_KEY)
        
        if '@' not in email or '.' not in email:
            flash("Invalid email format.", "danger")
            return render_template('login.html', home_url=url_for('home'), recaptcha_site_key=RECAPTCHA_SITE_KEY)

        try:
            user = db.users.find_one({"email": email})
            if user and check_password_hash(user['password'], password):
                session.clear()
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                logger.info(f"User logged in: {session['username']}")
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid email or password", "danger")
        except Exception as e:
            flash("An error occurred during login.", "danger")
            logger.error(f"Login error: {e}")

    return render_template('login.html', home_url=url_for('home'), recaptcha_site_key="6LdVOQgrAAAAAN_6n32KmQafE0nKBCKB_ZGpSWXk")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if not all([name, email, password, confirm_password]):
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))
        
        if '@' not in email or '.' not in email:
            flash("Invalid email format.", "danger")
            return redirect(url_for("register"))
        
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))
        
        if len(password) < 8:
            flash("Password must be at least 8 characters long!", "danger")
            return redirect(url_for("register"))
        
        try:
            existing_user = db.users.find_one({"email": email})
            if existing_user:
                flash("Email already registered!", "danger")
                return redirect(url_for("register"))
            
            hashed_pw = generate_password_hash(password)
            joined_date = datetime.now().strftime("%Y-%m-%d")
            db.users.insert_one({
                "username": name,
                "email": email,
                "password": hashed_pw,
                "favorites": [],
                "joined": joined_date,
                "profile_picture": ""
            })
            logger.info(f"New user registered: {email}")
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash("An error occurred during registration.", "danger")
            logger.error(f"Registration error: {e}")
    return render_template("register.html", home_url=url_for('home'))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("You must be logged in to access the dashboard.", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"], home_url=url_for('home'), login_url=url_for('login'))

@app.route("/admin_panel")
def admin_panel():
    try:
        users = list(db.users.find())
        for user in users:
            user['_id'] = str(user['_id'])
            activities = list(db.activities.find({"user_id": user['_id']}).sort("timestamp", -1).limit(5))
            user['activities'] = activities
        return render_template("admin.html", users=users, home_url=url_for('home'))
    except Exception as e:
        flash("Error loading admin panel.", "danger")
        logger.error(f"Admin panel error: {e}")
        return render_template("admin.html", users=[], home_url=url_for('home'))

@app.route("/delete_user/<user_id>", methods=["POST"])
def delete_user(user_id):
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "warning")
        return redirect(url_for("login"))
    try:
        if user_id == session["user_id"]:
            flash("You cannot delete your own account from the admin panel.", "danger")
            return redirect(url_for("admin_panel"))
        
        db.users.delete_one({"_id": ObjectId(user_id)})
        db.activities.delete_many({"user_id": user_id})
        logger.info(f"User deleted: {user_id}")
        flash("User deleted successfully.", "success")
    except Exception as e:
        flash("Error deleting user.", "danger")
        logger.error(f"Delete user error: {e}")
    return redirect(url_for("admin_panel"))

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/contact")
def contact():
    site_key = os.getenv("RECAPTCHA_SITE_KEY")
    return render_template("contact.html", home_url=url_for('home'), recaptcha_site_key=site_key)


@app.route("/submit_contact", methods=["POST"])
def submit_contact():
    """Handle contact form submission, validate CAPTCHA, save to database, and send email."""
    recaptcha_response = request.form.get("g-recaptcha-response")

    # Check if CAPTCHA was completed
    if not recaptcha_response:
        flash("Please complete the CAPTCHA.", "danger")
        return redirect(url_for("contact"))

    # Verify reCAPTCHA
    recaptcha_url = f"https://www.google.com/recaptcha/api/siteverify?secret={RECAPTCHA_SECRET_KEY}&response={recaptcha_response}"
    try:
        with urlopen(recaptcha_url) as response:
            result = json.loads(response.read().decode())
            logger.info(f"reCAPTCHA verification result: {result}")
            if not result.get("success"):
                flash("CAPTCHA verification failed. Please try again.", "danger")
                return redirect(url_for("contact"))
    except Exception as e:
        logger.error(f"Error verifying reCAPTCHA: {e}")
        flash("Error verifying CAPTCHA.", "danger")
        return redirect(url_for("contact"))

    # Get form data
    name = request.form.get("name")
    email = request.form.get("email")
    message = request.form.get("message")

    # Validate input
    if not all([name, email, message]):
        flash("All fields are required!", "danger")
        return redirect(url_for("contact"))

    if "@" not in email or "." not in email:
        flash("Invalid email format.", "danger")
        return redirect(url_for("contact"))

    # Save data to MongoDB
    try:
        db.contacts.insert_one({
            "name": name,
            "email": email,
            "message": message,
            "submitted_at": datetime.utcnow()
        })
        logger.info(f"Contact form submitted by: {email}")

        # Send email notification
        send_email(name, email, message)

        flash("Thank you for reaching out! We’ll get back to you soon.", "success")
    except Exception as e:
        logger.error(f"Error saving to database: {e}")
        flash("Error submitting contact form.", "danger")

    return redirect(url_for("contact"))


def send_email(name, email, message):
    """Send an email notification when a new contact form is submitted."""
    try:
        msg = Message(
            "New Contact Form Submission",
            sender=app.config["MAIL_DEFAULT_SENDER"],
            recipients=[app.config["MAIL_USERNAME"]]
        )
        msg.body = f"New contact form submission:\n\nName: {name}\nEmail: {email}\nMessage:\n{message}"
        mail.send(msg)
        logger.info("Contact form email sent successfully.")
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        raise e  # Helps debug SMTP issues

@app.route("/get_user_data")
def get_user_data():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401
    try:
        user = db.users.find_one({"_id": ObjectId(session["user_id"])})
        if user:
            return jsonify({
                "username": user["username"],
                "email": user["email"],
                "joined": user.get("joined", "N/A"),
                "profile_picture": user.get("profile_picture", "")
            })
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logger.error(f"Error fetching user data: {e}")
        return jsonify({"error": "Server error"}), 500

@app.route("/update_profile", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401
    try:
        data = request.get_json()
        new_username = data.get("username")
        new_email = data.get("email")
        profile_picture = data.get("profile_picture")
        if not new_username or not new_email:
            return jsonify({"error": "Username and email are required"}), 400
        
        if '@' not in new_email or '.' not in new_email:
            return jsonify({"error": "Invalid email format"}), 400
        
        existing_user = db.users.find_one({"email": new_email, "_id": {"$ne": ObjectId(session["user_id"])}})
        if existing_user:
            return jsonify({"error": "Email already in use"}), 400
        
        update_data = {"username": new_username, "email": new_email}
        if profile_picture:
            update_data["profile_picture"] = profile_picture
        
        result = db.users.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": update_data}
        )
        if result.modified_count > 0:
            session["username"] = new_username
            logger.info(f"Profile updated for user: {session['user_id']}")
            return jsonify({"success": True, "username": new_username, "email": new_email, "profile_picture": profile_picture})
        return jsonify({"error": "No changes made"}), 400
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        return jsonify({"error": "Server error"}), 500

@app.route("/get_favorites")
def get_favorites():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401
    try:
        user = db.users.find_one({"_id": ObjectId(session["user_id"])})
        favorites = [{"type": "music" if "song" in f else "event", "item": f} for f in user.get("favorites", [])]
        return jsonify({"favorites": favorites})
    except Exception as e:
        logger.error(f"Error fetching favorites: {e}")
        return jsonify({"error": "Failed to fetch favorites"}), 500

@app.route("/toggle_favorite", methods=["POST"])
def toggle_favorite():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.get_json()
    type = data.get("type")
    item = data.get("item")
    action = data.get("action")
    if not all([type, item, action]) or type not in ["music", "event"]:
        return jsonify({"error": "Invalid request"}), 400

    try:
        user = db.users.find_one({"_id": ObjectId(session["user_id"])})
        favorites = user.get("favorites", [])
        if action == "add":
            if item not in favorites:
                favorites.append(item)
                db.users.update_one({"_id": ObjectId(session["user_id"])}, {"$set": {"favorites": favorites}})
                logger.info(f"Favorite added: {item}")
                return jsonify({"success": True, "favorites": [{"type": type, "item": f} for f in favorites]})
            return jsonify({"error": "Item already in favorites"}), 400
        elif action == "remove":
            if item in favorites:
                favorites.remove(item)
                db.users.update_one({"_id": ObjectId(session["user_id"])}, {"$set": {"favorites": favorites}})
                logger.info(f"Favorite removed: {item}")
                return jsonify({"success": True, "favorites": [{"type": type, "item": f} for f in favorites]})
            return jsonify({"error": "Item not in favorites"}), 400
        else:
            return jsonify({"error": "Invalid action"}), 400
    except Exception as e:
        logger.error(f"Error toggling favorite: {e}")
        return jsonify({"error": "Failed to update favorites"}), 500

@app.route("/get_nostalgia_data", methods=["GET"])
def get_nostalgia_data():
    year = request.args.get("year", type=int)
    if not year or year < 1900 or year > datetime.now().year:
        return jsonify({"error": "Invalid year"}), 400

    errors = {}
    try:
        music_data = fetch_top_songs(year)
        if music_data is None:
            errors["music"] = "Failed to fetch music data after retries"
            music_data = []

        events_data = fetch_wikipedia_events(year)
        if events_data is None:
            events_data = []
            errors["events"] = "Failed to fetch events data after retries"
        else:
            events_data = [e["text"] for e in events_data]

        websites_data = fetch_websites(year)
        if websites_data is None:
            errors["websites"] = "Failed to fetch websites data after retries"
            websites_data = []
        else:
            websites_data = [
                {
                    "name": site["name"],
                    "url": site["url"] if site["url"] else None,
                    "timestamp": site["timestamp"] if site["timestamp"] else "N/A",
                    "error": site.get("error", None)
                }
                for site in websites_data
            ]

        response = {
            "year": year,
            "music": [f"{song['title']} by {song['artist']}" for song in music_data],
            "events": events_data,
            "websites": websites_data
        }
        if errors:
            response["errors"] = errors
            logger.warning(f"Partial data loaded with errors: {errors}")
            return jsonify(response), 206
        logger.info(f"Successfully loaded nostalgia data for year {year}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Unexpected error in get_nostalgia_data: {e}")
        return jsonify({"error": "Unexpected server error while fetching nostalgia data"}), 500

@app.route("/retry_nostalgia_data", methods=["POST"])
def retry_nostalgia_data():
    data = request.get_json()
    year = data.get("year", type=int)
    if not year or year < 1900 or year > datetime.now().year:
        return jsonify({"error": "Invalid year"}), 400

    errors = {}
    try:
        music_data = fetch_top_songs(year)
        if music_data is None:
            errors["music"] = "Failed to fetch music data after retries"
            music_data = []

        events_data = fetch_wikipedia_events(year)
        if events_data is None:
            events_data = []
            errors["events"] = "Failed to fetch events data after retries"
        else:
            events_data = [e["text"] for e in events_data]

        websites_data = fetch_websites(year)
        if websites_data is None:
            errors["websites"] = "Failed to fetch websites data after retries"
            websites_data = []
        else:
            websites_data = [
                {
                    "name": site["name"],
                    "url": site["url"] if site["url"] else None,
                    "timestamp": site["timestamp"] if site["timestamp"] else "N/A",
                    "error": site.get("error", None)
                }
                for site in websites_data
            ]

        response = {
            "year": year,
            "music": [f"{song['title']} by {song['artist']}" for song in music_data],
            "events": events_data,
            "websites": websites_data
        }
        if errors:
            response["errors"] = errors
            logger.warning(f"Retry partial data loaded with errors: {errors}")
            return jsonify(response), 206
        logger.info(f"Retry successfully loaded nostalgia data for year {year}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Unexpected error in retry_nostalgia_data: {e}")
        return jsonify({"error": "Unexpected server error while retrying nostalgia data"}), 500

# Fetch top songs with retry
@retry_on_failure(max_attempts=3, delay=2)
def fetch_top_songs(year):
    if not LASTFM_API_KEY:
        logger.error("LastFM API key missing")
        return None
    url = f"http://ws.audioscrobbler.com/2.0/?method=tag.gettoptracks&tag={year}&api_key={LASTFM_API_KEY}&format=json"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        logger.error(f"LastFM API error: {data['error']} - {data['message']}")
        return None
    if "tracks" in data and "track" in data["tracks"]:
        return [
            {
                "title": track["name"],
                "artist": track["artist"]["name"],
                "url": track["url"]
            }
            for track in data["tracks"]["track"][:5]
        ]
    logger.warning(f"No top songs found for year {year}")
    return []

# Fetch Wikipedia events with retry
@retry_on_failure(max_attempts=3, delay=2)
def fetch_wikipedia_events(year):
    url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{year}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    data = response.json()
    if "extract" in data:
        return [{"year": year, "text": data["extract"], "link": data["content_urls"]["desktop"]["page"]}]
    logger.warning(f"No Wikipedia extract found for year {year}")
    return []

# Fetch Wayback Machine snapshots for websites
@retry_on_failure(max_attempts=3, delay=2)
def fetch_websites(year):
    """Fetch archived snapshots of Google.com and YouTube.com for a given year."""
    websites = [
        {"name": "Google", "url": "https://google.com"},
        {"name": "YouTube", "url": "https://youtube.com"}
    ]
    archived_data = []

    for site in websites:
        try:
            # Construct the timestamp for the start of the year (e.g., 20200101000000 for Jan 1, 2020)
            timestamp = f"{year}0101000000"
            params = {
                "url":

 site["url"],
                "fl": "timestamp,original",  # Fields to return: timestamp and original URL
                "matchType": "exact",
                "limit": 1,  # Get the closest snapshot
                "from": timestamp,
                "to": f"{year}1231235959"  # End of the year
            }
            response = requests.get(WAYBACK_API_URL, params=params, timeout=10)
            response.raise_for_status()

            data = response.text.strip()
            if data:
                # Parse the CDX response (space-separated values)
                timestamp, original_url = data.split(" ", 1)
                archived_url = f"http://web.archive.org/web/{timestamp}/{original_url}"
                archived_data.append({
                    "name": site["name"],
                    "url": archived_url,
                    "timestamp": timestamp
                })
            else:
                logger.warning(f"No snapshot found for {site['name']} in {year}")
                archived_data.append({
                    "name": site["name"],
                    "url": None,
                    "timestamp": None,
                    "error": f"No snapshot available for {year}"
                })
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Wayback snapshot for {site['name']}: {e}")
            archived_data.append({
                "name": site["name"],
                "url": None,
                "timestamp": None,
                "error": "Failed to fetch snapshot"
            })

    return archived_data

if __name__ == "__main__":
    app.run(debug=True, port=5001)