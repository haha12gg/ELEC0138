from flask import Flask, request, redirect, render_template, url_for, session, flash, jsonify, make_response, get_flashed_messages
import boto3
from boto3.dynamodb.conditions import Attr
from datetime import datetime, timedelta
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
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_wtf import FlaskForm, form
from wtforms import StringField, PasswordField, SubmitField, HiddenField, RadioField
from wtforms.fields.simple import TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from flask_wtf.csrf import CSRFProtect
import hashlib




class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')




app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False
app.permanent_session_lifetime = timedelta(minutes=30)
app.config['SECRET_KEY'] = os.urandom(24).hex()

csrf = CSRFProtect(app)

# Configure DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='eu-west-2',
                          aws_access_key_id='AKIA4MTWN2ZSFUOUEKGY',
                          aws_secret_access_key='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')
table = dynamodb.Table('Account')
forum_table = dynamodb.Table('forums_weak')
confirm_table = dynamodb.Table('confirm')

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'wujunliang1102@gmail.com'
app.config['MAIL_PASSWORD'] = 'aerxmdoqfzhkahyx'
app.config['MAIL_DEFAULT_SENDER'] = 'wujunliang1102@gmail.com'
app.config['MAIL_USE_UNICODE'] = True

mail = Mail(app)


@app.route('/', methods=['GET', 'POST'])
@csrf.exempt
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    error = None
    account_id = request.form.get('account_id', '')
    password = request.form.get('password', '')
    message = get_flashed_messages()

    if request.method == 'POST':
        captcha = request.form.get('captcha', '')

        # Check password and captcha
        response = table.get_item(Key={'Email_address': account_id})
        if 'Item' not in response or hash_password(password) != response['Item']['password']:
            error = 'Invalid Credentials. Please try again.'
        elif captcha.lower() != session.get('captcha', '').lower():
            error = 'Invalid captcha. Please try again.'
        else:
            session['user'] = account_id
            session.permanent = True
            confirm_table.put_item(Item={
                'Email_address': account_id,
                'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Allowed': False
            })

            user = response['Item']
            if user.get('Authenticate', 'disabled') == 'disabled':
                return redirect(url_for('forum'))
            else:
                # Generate code
                s = Serializer(app.config['SECRET_KEY'], expires_in=300)  # expire in 5 mins
                token = s.dumps({'user_email': account_id}).decode('utf-8')
                authenticate_url = url_for('authenticate', token=token, _external=True)

                # send verification code and random code
                verification_code = generate_verification_code()
                random_code = generate_random_code()
                send_verification_email(account_id, verification_code, random_code, authenticate_url)
                session['verification_code'] = verification_code
                session['random_code'] = random_code

                return redirect(url_for('verify'))

    return render_template('login_s.html',
                           error=error,
                           show_captcha=True,
                           account_id=account_id,
                           password=password,
                           message=message)


@app.route('/registration', methods=['GET', 'POST'])
@csrf.exempt
def registration():
    error = None
    if request.method == 'POST':
        email_address = request.form['email_address']
        password = request.form['password']
        email_code = request.form['email_code']
        captcha = request.form.get('captcha', '')
        action = request.form.get('action')

        if action == "Send Code":
            # Check if email is registered
            response = table.get_item(Key={'Email_address': email_address})
            if 'Item' in response:
                error = 'This email address is already registered.'
            else:
                # send verification code
                verification_code = generate_verification_code()
                send_verification_email(email_address, verification_code, "")
                session['verification_code'] = verification_code

            return render_template('registration_s.html', email_address=email_address, password=password, error=error)

        if action == "Register":
            if email_code != session.get('verification_code'):
                error = 'Invalid email code. Please try again.'
            elif captcha.lower() != session.get('captcha', '').lower():
                error = 'Invalid captcha. Please try again.'
            else:
                # add account
                hashed_password = hash_password(password)
                table.put_item(Item={
                    'Email_address': email_address,
                    'password': hashed_password,
                    'Role': 'student',
                    'Authenticate': 'disabled'  # set default Authenticate as disabled
                })
                return redirect(url_for('login'))

    return render_template('registration_s.html', error=error)


@app.route('/waiting')
@csrf.exempt
def waiting():
    if 'user' not in session:
        return redirect(url_for('login'))

    return render_template('waiting.html')


@app.route('/check_access')
@csrf.exempt
def check_access():
    if 'user' not in session:
        return jsonify({'allowed': False})

    response = confirm_table.get_item(Key={'Email_address': session['user']})
    item = response.get('Item')

    if item and item.get('Allowed'):
        allowed_time = datetime.strptime(item['AllowedTime'], '%Y-%m-%d %H:%M:%S')
        if (datetime.now() - allowed_time).total_seconds() <= 30 * 60:
            return jsonify({'allowed': True})
        else:
            confirm_table.delete_item(Key={'Email_address': session['user']})
            confirm_table.put_item(Item={
                'Email_address': session['user'],
                'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Allowed': False
            })

    return jsonify({'allowed': False})


@app.route('/verify', methods=['GET', 'POST'])
@csrf.exempt
def verify():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_email = session['user']
    error = None

    if request.method == 'POST':
        verification_code = request.form['verification_code']

        if verification_code == session.get('verification_code'):
            return redirect(url_for('waiting'))
        else:
            error = 'Invalid verification code. Please try again.'

    return render_template('verify.html', error=error)


@app.route('/authenticate/<token>', methods=['GET', 'POST'])
@csrf.exempt
def authenticate(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        return 'Invalid or expired token'

    user_email = data['user_email']
    session['user'] = user_email

    error = None

    if request.method == 'POST':
        random_code = request.form['random_code']
        email = request.form['email']

        if email == user_email and random_code == session.get('random_code'):
            return redirect(url_for('confirm'))
        else:
            error = 'Invalid email or random code. Please try again.'

    return render_template('authenticate.html', error=error, user_email=user_email)


@app.route('/confirm', methods=['GET', 'POST'])
@csrf.exempt
def confirm():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        email = request.form['email']
        action = request.form['action']

        if action == 'Allow':
            confirm_table.update_item(
                Key={'Email_address': email},
                UpdateExpression='SET #allowed = :val, #allowedTime = :time',
                ExpressionAttributeNames={'#allowed': 'Allowed', '#allowedTime': 'AllowedTime'},
                ExpressionAttributeValues={':val': True, ':time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            )
        elif action == 'Deny':
            confirm_table.delete_item(Key={'Email_address': email})

    # get request
    response = confirm_table.scan(FilterExpression=Attr('Email_address').eq(session['user']) & Attr('Allowed').eq(False))
    requests = response.get('Items', [])

    return render_template('confirm.html', requests=requests)


@app.route('/profile')
@csrf.exempt
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_email = session['user']
    user = table.get_item(Key={'Email_address': user_email}).get('Item', {})
    authenticate_status = user.get('Authenticate', 'disabled')

    return render_template('profile.html', user_email=user_email, authenticate_status=authenticate_status)


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    form = ChangePasswordForm()
    user_email = session['user']

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        # get user information
        user = table.get_item(Key={'Email_address': user_email}).get('Item', {})

        if hash_password(current_password) != user['password']:
            form.current_password.errors.append('Current password is incorrect.')
        else:
            # update password
            hashed_new_password = hash_password(new_password)
            table.update_item(
                Key={'Email_address': user_email},
                UpdateExpression='SET password = :val',
                ExpressionAttributeValues={':val': hashed_new_password}
            )
            logout()
            flash('Password changed successfully. Please login again.')
            return redirect(url_for('login'))

    return render_template('change_password.html', form=form)


@app.route('/toggle_authenticate', methods=['POST'])
@csrf.exempt
def toggle_authenticate():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_email = session['user']
    authenticate_status = request.form['authenticate_status']

    if authenticate_status == 'disabled':
        new_status = 'enabled'
    else:
        new_status = 'disabled'

    table.update_item(
        Key={'Email_address': user_email},
        UpdateExpression='SET Authenticate = :val',
        ExpressionAttributeValues={':val': new_status}
    )

    return redirect(url_for('profile'))


@app.route('/forum')
@csrf.exempt
def forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get forums
    response = forum_table.scan(
        FilterExpression=Attr('Associate').eq('None'),
    )
    forums = response.get('Items', [])
    forums.sort(key=lambda x: x['Date'], reverse=True)

    # Get current role and check if turn on the MFA
    user_role = table.get_item(Key={'Email_address': session['user']}).get('Item', {}).get('Role', 'student')
    mfa_enabled = table.get_item(Key={'Email_address': session['user']}).get('Item', {}).get('Authenticate', 'disabled') == 'enabled'
    return render_template('forum_w.html', forums=forums, user_role=user_role, mfa_enabled=mfa_enabled, session=session)
    # return render_template('forum_w.html', forums=forums, user_role=user_role)


@app.route('/create_forum', methods=['GET', 'POST'])
@csrf.exempt
def create_forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        topic = request.form['topic']
        content = request.form['content']
        # Create Forum
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


@app.route('/delete_forum', methods=['POST'])
@csrf.exempt
def delete_forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    forum_id = request.form['forum_id']
    forum_date = request.form['forum_date']

    # Get the forum
    forum = forum_table.get_item(Key={'ID': forum_id, 'Date': forum_date}).get('Item', {})

    # Check if the user is admin or the author of the forum
    user_email = session['user']
    user_role = table.get_item(Key={'Email_address': user_email}).get('Item', {}).get('Role', 'student')

    if user_role != 'admin' and forum.get('Author') != user_email:
        flash('You do not have permission to delete this forum.')
        return redirect(url_for('forum'))

    # Delete Main Forum
    forum_table.delete_item(Key={'ID': forum_id, 'Date': forum_date})

    # Delete associate Forum
    replies = forum_table.scan(
        FilterExpression=Attr('Associate').eq(forum_id)
    ).get('Items', [])

    for reply in replies:
        forum_table.delete_item(Key={'ID': reply['ID'], 'Date': reply['Date']})

    return redirect(url_for('forum'))


@app.route('/forum_specific')
@csrf.exempt
def forum_specific():
    if 'user' not in session:
        return redirect(url_for('login'))
    id = request.args.get('id')
    date = request.args.get('date')

    # Get specific forum
    response = forum_table.get_item(Key={'ID': id, 'Date': date})
    forum = response.get('Item', {})

    # Get replies
    replies = forum_table.scan(
        FilterExpression=Attr('Associate').eq(id)
    ).get('Items', [])
    replies.sort(key=lambda x: x['Date'], reverse=False)

    return render_template('forum_specific_w.html', forum=forum, replies=replies,session=session)


@app.route('/delete_reply', methods=['POST'])
@csrf.exempt
def delete_reply():
    if 'user' not in session:
        return redirect(url_for('login'))

    reply_id = request.form['reply_id']
    reply_date = request.form['reply_date']
    forum_id = request.form['forum_id']
    forum_date = request.form['forum_date']

    # Get the reply
    reply = forum_table.get_item(Key={'ID': reply_id, 'Date': reply_date}).get('Item', {})

    # Check if the user is admin or the author of the reply
    user_email = session['user']
    user_role = table.get_item(Key={'Email_address': user_email}).get('Item', {}).get('Role', 'student')

    if user_role != 'admin' and reply.get('Author') != user_email:
        flash('You do not have permission to delete this reply.')
    else:
        # Delete reply
        forum_table.delete_item(Key={'ID': reply_id, 'Date': reply_date})

        # Update number of replies
        forum_table.update_item(
            Key={
                'ID': forum_id,
                'Date': forum_date
            },
            UpdateExpression='SET Replys = Replys - :val',
            ExpressionAttributeValues={':val': 1}
        )

    return redirect(url_for('forum_specific', id=forum_id, date=forum_date))


@app.route('/edit_reply/<reply_id>/<reply_date>/<forum_id>/<forum_date>', methods=['GET', 'POST'])
@csrf.exempt
def edit_reply(reply_id, reply_date, forum_id, forum_date):
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']
        forum_table.update_item(
            Key={
                'ID': reply_id,
                'Date': reply_date
            },
            UpdateExpression='SET Content = :val',
            ExpressionAttributeValues={':val': content}
        )
        return redirect(url_for('forum_specific', id=forum_id, date=forum_date))

    reply = forum_table.get_item(Key={'ID': reply_id, 'Date': reply_date}).get('Item', {})
    return render_template('edit_reply.html', reply=reply, forum_id=forum_id, forum_date=forum_date)


@app.route('/logout')
@csrf.exempt
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/reply', methods=['POST'])
@csrf.exempt
def post_reply():
    if 'user' not in session:
        flash('Please log in to reply.')
        return redirect(url_for('login'))

    forum_id = request.form['forum_id']
    forum_date = request.form['forum_date']

    content = request.form['content']
    user_email = session['user']

    # Add reply to DB
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

    # update number of replies
    forum_table.update_item(
        Key={
            'ID': forum_id,
            'Date': forum_date
        },
        UpdateExpression='SET Replys = Replys + :val',
        ExpressionAttributeValues={':val': 1}
    )

    return redirect(url_for('forum_specific', id=forum_id, date=forum_date))


@app.route('/captcha')
@csrf.exempt
def captcha():
    # Generate captcha image
    captcha_text = generate_captcha()
    captcha_image = generate_captcha_image(captcha_text)

    # store in session
    session['captcha'] = captcha_text
    img_io = BytesIO()
    captcha_image.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')


@app.template_filter('formatdatetime')
def format_datetime_filter(datetime_str):
    return datetime_str.replace('T', ' ').replace('Z', '')


def generate_verification_code():
    characters = ''.join(random.choices(string.digits, k=6))
    return characters


def generate_random_code():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=24))


def send_verification_email(email, code, random_code, authenticate_url=""):
    msg = Message('Verification Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
    if authenticate_url:
        msg.body = f'Your verification code is: {code}\nYour random code is: {random_code}\n\nPlease click the following link to authenticate (valid for 5 minutes): {authenticate_url}'.encode('utf-8')
    else:
        msg.body = f'Your verification code is: {code}'.encode('utf-8')
    mail.send(msg)


def generate_captcha():
    captcha_text = ''.join(random.choices(string.digits, k=6))
    return captcha_text


def generate_captcha_image(captcha_text):
    image = ImageCaptcha()
    captcha_data = image.generate(captcha_text)
    captcha_image = Image.open(captcha_data)
    return captcha_image


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


if __name__ == '__main__':
    # app.run(ssl_context='adhoc')
    app.run(debug=True)