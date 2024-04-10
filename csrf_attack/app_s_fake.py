# app_fake.py
from flask import Flask, render_template

app1 = Flask(__name__)

@app1.route('/changepassword')
def csrf_demo():
    # 假设 csrf.html 在这个应用的 templates 文件夹内
    return render_template('csrf_s.html')

@app1.route('/change_password')
def csrf_demo1():
    # 假设 csrf.html 在这个应用的 templates 文件夹内
    return render_template('csrf_w.html')

if __name__ == '__main__':
    app1.run(debug=True, port=5001)
