from flask import Flask, request, redirect, render_template, url_for, session
import boto3
from boto3.dynamodb.conditions import Attr
from datetime import datetime
import uuid,os


app = Flask(__name__)
app.secret_key = os.urandom(24)
# 配置DynamoDB
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
    if request.method == 'POST':
        account_id = request.form['account_id']
        password = request.form['password']
        action = request.form.get('action')

        if action == "Login":
            # 检查账号和密码
            response = table.get_item(Key={'Email_address': account_id})
            if 'Item' in response and response['Item']['password'] == password:
                session['user'] = account_id  # 登录成功，设置用户session
                return redirect(url_for('forum'))
            else:
                error = 'Invalid Credentials. Please try again.'
    return render_template('login_w.html', error=error)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        email_address = request.form['email_address']
        password = request.form['password']

        # 添加账号
        table.put_item(Item={
            'email_address': email_address,
            'password': password,
            'Role': 'student'
        })

        return redirect(url_for('login'))

    return render_template('registration_w.html')


@app.route('/forum')
def forum():
    if 'user' not in session:
        return redirect(url_for('login'))

    # 从DynamoDB获取论坛帖子
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
            'Author': session['user'],  # 假设已通过登录流程设置
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
    print("ID here")
    print(id)
    # 获取指定的论坛帖子
    response = forum_table.get_item(Key={'ID': id,'Date':date})
    forum = response.get('Item', {})

    # 获取回复
    replies = forum_table.scan(
        FilterExpression=Attr('Associate').eq(id)
    ).get('Items', [])
    replies.sort(key=lambda x: x['Date'], reverse=True)

    return render_template('forum_specific_w.html', forum=forum, replies=replies)

@app.route('/logout')
def logout():
    session.pop('user', None)  # 移除用户session
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
