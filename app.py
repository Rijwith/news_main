from flask import Flask, redirect, request, session, url_for, render_template
from google_auth_oauthlib.flow import Flow
import psycopg2
from newspaper import Article
import nltk
from nltk import pos_tag, word_tokenize, sent_tokenize
import json
from bs4 import BeautifulSoup
import re
from flask_bcrypt import Bcrypt

# Initialize Flask app
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "Dakshana123"

# Initialize NLTK
nltk.download('all')
nltk.download('averaged_perceptron_tagger')
nltk.download("stopwords")
nltk.download("punkt")
nltk.download('universal_tagset')

# Database configuration
db_config = {
    'dbname': 'rijwith',
    'user': 'rijwith_user',
    'password': 'UvyQDcIethetCUanjc30wkaOTjiebVt5',
    'host': 'dpg-cnmmc4q1hbls739hahig-a',
    'port': '5432'
}

# Path to the client secrets file
client_secrets_file = 'app.json'

# Scopes define the level of access you are requesting from the user
scopes = ['https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/userinfo.email',
          'openid']

# Redirect URI for the OAuth flow
redirect_uri = 'https://news-main.onrender.com/callback'

# Create the OAuth flow object
flow = Flow.from_client_secrets_file(client_secrets_file, scopes=scopes, redirect_uri=redirect_uri)


# Route for the main portal page
@app.route('/')
def portal():

    return render_template('index2.html')

# google authentication process
@app.route('/login')
def login():
    if 'google_token' in session:
        # User is already authenticated, redirect to a protected route
        return redirect(url_for('protected'))
    else:
        # User is not authenticated, render the ggl.html template
        authorization_url, _ = flow.authorization_url(prompt='consent')
        return redirect(authorization_url)

# Callback route for handling OAuth response
@app.route('/callback')
def callback():
    # Handle the callback from the Google OAuth flow
    flow.fetch_token(code=request.args.get('code'))
    session['google_token'] = flow.credentials.token

    # Redirect to the protected route or another page
    return redirect(url_for('protected'))

# Protected route accessible only to authenticated users
@app.route('/protected')
def protected():
    if 'google_token' in session:
        return render_template("submit_url.html", data=0) 
    else:
        # User is not authenticated, redirect to the portal page
        return redirect(url_for('portal'))

# simple valid Gmail address function
def is_valid_gmail(email):
    gmail_pattern = re.compile(r'^[a-zA-Z0-9_.+-]+@gmail\.com$')
    return bool(gmail_pattern.match(email))

# user signup credentials
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        dob = request.form['dob']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the Gmail address is valid
        if is_valid_gmail(email):
            if password == confirm_password and len(password) >= 8:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                # Store user details in the database
                conn = psycopg2.connect(**db_config)
                cursor = conn.cursor()
                cursor.execute("INSERT INTO user_credentials (name, dob, username, email, password) VALUES (%s, %s, %s, %s, %s)",
                    (name, dob, username, email, hashed_password))
                conn.commit()
                conn.close()

                return redirect(url_for('index2'))
            
            return render_template('signup.html', error="Invalid password or password confirmation. Please use a valid password (minimum length: 8 characters) and ensure passwords match.")
        
        return render_template('signup.html', error='Invalid Gmail address. Please use a valid Gmail address.')

    return render_template('signup.html')

# UserLogin route
@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']

        # Check if the login credentials are valid
        user = get_user_by_username_or_email(username_or_email)
        if user and bcrypt.check_password_hash(user['password'], password):
            # Store user information in the session
            
            session['username'] = user['username']
            session['email'] = user['email']

            return redirect(url_for('submit_url'))

        return render_template('user_login.html', error="Invalid login credentials. Please try again.")

    return render_template('user_login.html')

# Function to get user by username or email
def get_user_by_username_or_email(username_or_email):
    conn = psycopg2.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT name, dob, username, email, password FROM user_credentials WHERE username = %s OR email = %s", (username_or_email, username_or_email))
    user_tuple = cursor.fetchone()
    conn.close()

    if user_tuple:
        user_dict = {
            'name': user_tuple[0],
            'dob': user_tuple[1],
            'username': user_tuple[2],
            'email': user_tuple[3],
            'password': user_tuple[4]
        }
        return user_dict
    else:
        return None

# Function to clean news text
def clean_news_text(news_text):
    # Remove unwanted characters (non-alphanumeric and extra spaces)
    cleaned_text = re.sub(r'[^\w\s.,?!]', '', news_text)
    cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()

    return cleaned_text

# submit_url 
@app.route('/submit_url', methods=['GET','POST'])
def submit_url():
    if request.method == 'POST':
        url = request.form['url']

        # Extract news text using newspaper3k
        article = Article(url)
        article.download()
        article.parse()
        news_text = article.text

        # Clean the news text
        cleaned_text = clean_news_text(news_text)

        # Analyze the text
        words = word_tokenize(cleaned_text)
        num_sentences = len(sent_tokenize(cleaned_text))
        num_words = len(words)
        pos_tags_tuples = nltk.pos_tag(words, tagset='universal')
        stop_words = len(nltk.corpus.stopwords.words('english'))

        # Convert POS tags to dict (word, upos_tag) for display
        pos_tag = {}
        for word, pos in pos_tags_tuples:
            if pos in pos_tag:
                pos_tag[pos] += 1
            else:
                pos_tag[pos] = 1

        desired_pos_tags = ['NOUN', 'ADV', 'VERB', 'PRON','NUM','ADP', 'DET', 'ADJ','CONJ', '.']
        pos_tags_dict = {pos: pos_tag.get(pos, 0) for pos in desired_pos_tags}

        json_data = json.dumps(pos_tags_dict)

        # Store the data in the database
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO news_data (url, news_text, Number_of_Sentences, Number_of_Words, stop_words, analysis_summary) VALUES (%s, %s, %s, %s, %s, %s)""",
                    (url, cleaned_text, num_sentences, num_words, stop_words, json_data))
        conn.commit()
        conn.close()

        # Save URL to session for viewing history
        session['submitted_urls'] = session.get('submitted_urls', []) + [url]

        return render_template('analysis_result.html', url=url, num_sentences=num_sentences, num_words=num_words, stop_words=stop_words, pos_tags_dict=pos_tags_dict, cleaned_text=cleaned_text)
    
    return render_template('submit_url.html')  # Display the form for submitting URLs

# admin login to view url history
@app.route('/admin_login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        try:
            username, email, password = (
                request.form['username'],
                request.form['email'],
                request.form['password']
            )

            # For simplicity, hardcoding a password here (you should use a more secure method)
            if username == 'Rijwith Mamidi' and password == '1234' and email == 'rijwith0417@gmail.com':
                session['admin'] = True
                return redirect(url_for('view_history'))
            else:
                return render_template('admin_login.html', error="Incorrect credentials. Access denied.")
        except KeyError as e:
            return render_template('admin_login.html', error="Missing form field. Please ensure all fields are filled.")
    return render_template('admin_login.html')

# history page after entering admin 
@app.route('/view_history')
def view_history():
    if 'admin' in session and session['admin']:
        # Admin user, so they can view the history
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT url, analysis_summary FROM news_data")
        history_data = cursor.fetchall()
        conn.close()
        return render_template('view_history.html', history_data=history_data)

    return "Access denied. Only admin can view the history."

# logout and redirect to submit_url page
@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('portal'))

# Run the Flask app
if __name__ == 'main':
    app.run(debug=True)
