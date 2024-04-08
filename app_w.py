from flask import Flask, request, redirect, render_template, url_for, session,flash, get_flashed_messages
import boto3
from boto3.dynamodb.conditions import Attr
from datetime import datetime
import uuid,os


app = Flask(__name__)
app.secret_key = os.urandom(24)
# DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='eu-west-2',
                          aws_access_key_id='AKIA4MTWN2ZSFUOUEKGY',
                          aws_secret_access_key='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')
table = dynamodb.Table('account_weak')
forum_table = dynamodb.Table('forums_weak')

@app.route('/', methods=['GET', 'POST'])
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    message = get_flashed_messages()
    if request.method == 'POST':
        account_id = request.form['account_id']
        password = request.form['password']
        action = request.form.get('action')

        if action == "Login":
            # check password
            response = table.get_item(Key={'Email_address': account_id})
            if 'Item' in response and response['Item']['password'] == password:
                session['user'] = account_id  # set session
                return redirect(url_for('forum'))
            else:
                error = 'Invalid Credentials. Please try again.'
    return render_template('login_w.html', error=error, message=message)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        email_address = request.form['email_address']
        password = request.form['password']

        # add account
        table.put_item(Item={
            'Email_address': email_address,
            'password': password,
            'Role': 'student'
        })

        return redirect(url_for('login'))

    return render_template('registration_w.html')


@app.route('/forum')
def forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    # get forums
    response = forum_table.scan(
        FilterExpression=Attr('Associate').eq('None'),
    )
    forums = response.get('Items', [])
    forums.sort(key=lambda x: x['Date'], reverse=True)  # sort by date

    return render_template('forum_w.html', forums=forums)


@app.route('/create_forum', methods=['GET', 'POST'])
def create_forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        topic = request.form['topic']
        content = request.form['content']
        # create forum
        forum_table.put_item(Item={
            'ID': str(uuid.uuid4()),
            'Date': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'Author': session['user'],
            'Content': content,
            'Replys': 0,
            'Associate': 'None',
            'Topic': topic
        })
        return redirect(url_for('forum'))

    return render_template('create_forum_w.html')

@app.route('/forum_specific')
def forum_specific():
    if 'user' not in session:
        return redirect(url_for('login'))
    id = request.args.get('id')
    date = request.args.get('date')
    # print("ID here")
    # print(id)
    # get specific forum
    response = forum_table.get_item(Key={'ID': id,'Date':date})
    forum = response.get('Item', {})

    # get replys
    replies = forum_table.scan(
        FilterExpression=Attr('Associate').eq(id)
    ).get('Items', [])
    replies.sort(key=lambda x: x['Date'], reverse=False)

    return render_template('forum_specific_w.html', forum=forum, replies=replies)

@app.route('/logout')
def logout():
    session.pop('user', None)  # pop session
    return redirect(url_for('login'))

@app.route('/reply', methods=['POST'])
def post_reply():
    if 'user' not in session:
        # if not log in
        flash('Please log in to reply.')
        return redirect(url_for('login'))

    forum_id = request.form['forum_id']
    forum_date = request.form['forum_date']

    content = request.form['content']
    user_email = session['user']

    # 添加回复到DynamoDB
    reply_id = str(uuid.uuid4())
    current_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    forum_table.put_item(Item={
        'ID': reply_id,
        'Date': current_time,
        'Author': user_email,
        'Content': content,
        'Replys': 0,
        'Associate': forum_id,
        'Topic': ''
    })

    # update count
    forum_table.update_item(
        Key={
            'ID': forum_id,
            'Date': forum_date
        },
        UpdateExpression='SET Replys = Replys + :val',
        ExpressionAttributeValues={':val': 1}
    )

    return redirect(url_for('forum_specific', id=forum_id, date=forum_date))

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_email = session['user']
    user = table.get_item(Key={'Email_address': user_email}).get('Item', {})

    return render_template('profile_w.html', user_email=user_email)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_email = session['user']
    error = None

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']


        if new_password != confirm_password:
            error = 'New password and confirm password do not match.'
        else:
            table.update_item(
                Key={'Email_address': user_email},
                UpdateExpression='SET password = :val',
                ExpressionAttributeValues={':val': new_password}
            )
            logout()
            flash('Password changed successfully. Please log in again.')
            return redirect(url_for('login'))

    return render_template('change_password_w.html', error=error)


@app.template_filter('formatdatetime')
def format_datetime_filter(datetime_str):
    return datetime_str.replace('T', ' ').replace('Z', '')

if __name__ == '__main__':
    app.run(debug=True)
