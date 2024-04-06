from flask import Flask, request, redirect, render_template, url_for, session, flash
import mysql.connector
from datetime import datetime
import uuid, os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 配置MySQL数据库连接
db_config = {
    'host': 'app-w.cpy042a08l8b.eu-west-2.rds.amazonaws.com',
    'user': 'admin',
    'password': 'admin12345',
    'database': 'app-w'
}

def get_db_connection():
    connection = mysql.connector.connect(**db_config)
    return connection

@app.route('/', methods=['GET', 'POST'])
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        account_id = request.form['account_id']
        password = request.form['password']
        action = request.form.get('action')

        if action == "Login":
            query = f"SELECT * FROM account_weak WHERE email_address = '{account_id}' AND password = '{password}'"
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query)
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            if user:
                session['user'] = account_id
                return redirect(url_for('forum'))
            else:
                error = 'Invalid Credentials. Please try again.'
    return render_template('login_w.html', error=error)

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        email_address = request.form['email_address']
        password = request.form['password']

        query = f"INSERT INTO account_weak (email_address, password, role) VALUES ('{email_address}', '{password}', 'student')"
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('login'))

    return render_template('registration_w.html')

@app.route('/forum')
def forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    query = "SELECT * FROM forums_weak WHERE Associate = 'None' ORDER BY Date DESC"
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query)
    forums = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('forum_w.html', forums=forums)

@app.route('/create_forum', methods=['GET', 'POST'])
def create_forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        topic = request.form['topic']
        content = request.form['content']
        forum_id = str(uuid.uuid4())
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        query = f"INSERT INTO forums_weak (ID, Date, Author, Content, Replies, Associate, Topic) VALUES ('{forum_id}', '{current_time}', '{session['user']}', '{content}', 0, 'None', '{topic}')"
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('forum'))

    return render_template('create_forum_w.html')

@app.route('/forum_specific')
def forum_specific():
    if 'user' not in session:
        return redirect(url_for('login'))
    forum_id = request.args.get('id')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    forum_query = f"SELECT * FROM forums_weak WHERE ID = '{forum_id}'"
    cursor.execute(forum_query)
    forum = cursor.fetchone()

    replies_query = f"SELECT * FROM forums_weak WHERE Associate = '{forum_id}' ORDER BY Date"
    cursor.execute(replies_query)
    replies = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('forum_specific_w.html', forum=forum, replies=replies)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/reply', methods=['POST'])
def post_reply():
    if 'user' not in session:
        flash('Please log in to reply.')
        return redirect(url_for('login'))

    forum_id = request.form['forum_id']
    content = request.form['content']
    reply_id = str(uuid.uuid4())
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    query = f"INSERT INTO forums_weak (ID, Date, Author, Content, Replies, Associate, Topic) VALUES ('{reply_id}', '{current_time}', '{session['user']}', '{content}', 0, '{forum_id}', '')"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()

    update_query = f"UPDATE forums_weak SET Replies = Replies + 1 WHERE ID = '{forum_id}'"
    cursor.execute(update_query)
    conn.commit()

    cursor.close()
    conn.close()

    return redirect(url_for('forum_specific', id=forum_id))

@app.template_filter('formatdatetime')
def format_datetime_filter(datetime_str):
    if isinstance(datetime_str, str):
        return datetime_str.replace('T', ' ').replace('Z', '')
    return datetime_str

if __name__ == '__main__':
    app.run(debug=True)
