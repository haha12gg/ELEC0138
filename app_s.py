from flask import Flask, request, redirect, render_template, url_for, session, flash, jsonify,make_response
import boto3
from boto3.dynamodb.conditions import Attr
from datetime import datetime,timedelta
import uuid, os, random, string
from flask_mail import Mail, Message
from captcha.image import ImageCaptcha
import io
import base64
from PIL import Image
from random import randint
from io import BytesIO
from flask import send_file
from urllib.parse import urlencode


app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False
app.permanent_session_lifetime = timedelta(minutes=30)

# DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='eu-west-2',
                          aws_access_key_id='AKIA4MTWN2ZSFUOUEKGY',
                          aws_secret_access_key='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')
table = dynamodb.Table('account_weak')
forum_table = dynamodb.Table('forums_weak')
confirm_table = dynamodb.Table('confirm')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'wujunliang1102@gmail.com'
app.config['MAIL_PASSWORD'] = 'aerxmdoqfzhkahyx'
app.config['MAIL_DEFAULT_SENDER'] = 'wujunliang1102@gmail.com'

mail = Mail(app)

@app.route('/', methods=['GET', 'POST'])
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    account_id = request.form.get('account_id', '')
    password = request.form.get('password', '')

    if request.method == 'POST':
        email_code = request.form['email_code']
        captcha = request.form.get('captcha', '')
        action = request.form.get('action')

        if action == "Send Code":
            # 发送邮箱验证码
            verification_code = generate_verification_code()
            random_code = generate_random_code()
            auth_id = str(uuid.uuid4())  # 生成唯一的认证 ID
            auth_expiry = datetime.now() + timedelta(minutes=5)  # 设置认证链接的过期时间
            auth_params = urlencode({'auth_id': auth_id, 'expiry': auth_expiry.strftime('%Y-%m-%d %H:%M:%S')})
            authenticate_url = url_for('authenticate', _external=True) + '?' + auth_params
            send_verification_email(account_id, verification_code, random_code, authenticate_url)
            session['verification_code'] = verification_code
            session['random_code'] = random_code
            session['auth_id'] = auth_id
            session['auth_expiry'] = auth_expiry.strftime('%Y-%m-%d %H:%M:%S')

            return render_template('login_w.html', show_captcha=True, account_id=account_id, password=password)

        if action == "Login":
            # 检查账号、密码
            response = table.get_item(Key={'Email_address': account_id})
            if 'Item' not in response or response['Item']['password'] != password:
                error = 'Invalid Credentials. Please try again.'
            elif email_code != session.get('verification_code'):
                error = 'Invalid email code. Please try again.'
            elif captcha.lower() != session.get('captcha', '').lower():
                error = 'Invalid captcha. Please try again.'
            else:
                session['user'] = account_id
                session.permanent = True  # 设置session为永久性的
                confirm_table.put_item(Item={
                    'Email_address': account_id,
                    'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'Allowed': False
                })
                return redirect(url_for('waiting'))

    return render_template('login_w.html', error=error, show_captcha=True, account_id=account_id, password=password)

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    error = None
    if request.method == 'POST':
        email_address = request.form['email_address']
        password = request.form['password']
        email_code = request.form['email_code']
        captcha = request.form.get('captcha', '')
        action = request.form.get('action')

        if action == "Send Code":
            # Check if email address is registered
            response = table.get_item(Key={'Email_address': email_address})
            if 'Item' in response:
                error = 'This email address is already registered.'
            else:
                # send verification code
                verification_code = generate_verification_code()
                send_verification_email(email_address, verification_code, "")
                session['verification_code'] = verification_code

            return render_template('registration_w.html', email_address=email_address, password=password, error=error)

        if action == "Register":
            if email_code != session.get('verification_code'):
                error = 'Invalid email code. Please try again.'
            elif captcha.lower() != session.get('captcha', '').lower():
                error = 'Invalid captcha. Please try again.'
            else:
                # register account
                table.put_item(Item={
                    'Email_address': email_address,
                    'password': password,
                    'Role': 'student'
                })
                return redirect(url_for('login'))

    return render_template('registration_w.html', error=error)


@app.route('/forum')
def forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get forums from DB
    response = forum_table.scan(
        FilterExpression=Attr('Associate').eq('None'),
    )
    forums = response.get('Items', [])
    forums.sort(key=lambda x: x['Date'], reverse=True)  # 确保按日期降序

    return render_template('forum_w.html', forums=forums)


@app.route('/create_forum', methods=['GET', 'POST'])
def create_forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        topic = request.form['topic']
        content = request.form['content']
        # 创建帖子
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

    # get replies
    replies = forum_table.scan(
        FilterExpression=Attr('Associate').eq(id)
    ).get('Items', [])
    replies.sort(key=lambda x: x['Date'], reverse=False)

    return render_template('forum_specific_w.html', forum=forum, replies=replies)

@app.route('/logout')
def logout():
    session.pop('user', None)  # 移除用户session
    return redirect(url_for('login'))

@app.route('/reply', methods=['POST'])
def post_reply():
    if 'user' not in session:
        # If not login
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

    # update replies count
    forum_table.update_item(
        Key={
            'ID': forum_id,
            'Date': forum_date
        },
        UpdateExpression='SET Replys = Replys + :val',
        ExpressionAttributeValues={':val': 1}
    )

    return redirect(url_for('forum_specific', id=forum_id, date=forum_date))

def captcha():
    # generate captcha image
    captcha_text = generate_captcha()
    captcha_image = generate_captcha_image(captcha_text)

    # store code into session
    session['captcha'] = captcha_text
    img_io = BytesIO()
    captcha_image.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')


@app.template_filter('formatdatetime')
def format_datetime_filter(datetime_str):
    return datetime_str.replace('T', ' ').replace('Z', '')

def generate_verification_code():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=6))


def generate_random_code():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=24))


def generate_verification_code():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=6))


def generate_random_code():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=24))


def send_verification_email(email, code, random_code):
    authenticate_url = url_for('authenticate', _external=True)
    msg = Message('Verification Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your verification code is: {code}\nYour random code is: {random_code}\n\nPlease click the following link to authenticate: {authenticate_url}'
    mail.send(msg)


def generate_captcha():
    # captcha_text = ''.join(random.choices(string.digits, k=6))
    return '123456'


def generate_captcha_image(captcha_text):
    image = ImageCaptcha()
    captcha_data = image.generate(captcha_text)
    captcha_image = Image.open(captcha_data)
    return captcha_image

if __name__ == '__main__':
    app.run(debug=True)
