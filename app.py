from flask import Flask, render_template, request, redirect, session, url_for, flash
import requests
from bs4 import BeautifulSoup
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# 加载 .env 文件中的环境变量
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 用于保护会话

# 配置数据库连接

# 构建 SQLALCHEMY_DATABASE_URI
db_username = os.getenv("DB_USERNAME")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_name = os.getenv("DB_NAME")

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_username}:{db_password}@{db_host}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 配置 OAuth 相关信息
client_id = os.getenv('OAUTH_CLIENT_ID')
client_secret = os.getenv('OAUTH_CLIENT_SECRET')  # 从环境变量获取 Client Secret
token_url = 'https://connect.linux.do/oauth2/token'
user_info_url = 'https://connect.linux.do/api/user'

# 定义用户模型
class User(db.Model):
    id = db.Column(db.String(50), primary_key=True)  # 假设用户 ID 是字符串类型
    username = db.Column(db.String(100), nullable=False)
    trust_level = db.Column(db.Integer, nullable=False)
    emails = db.relationship('Email', backref='user', lazy=True)

    def __init__(self, id, username, trust_level):
        self.id = id
        self.username = username
        self.trust_level = trust_level

# 定义邮箱模型
class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 记录邮箱创建时间

# OAuth 回调处理
@app.route('/oauth/callback')
def oauth_callback():
    code = request.args.get('code')
    if code is None:
        return "Authorization failed.", 400

    # 使用授权码交换访问令牌
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': url_for('oauth_callback', _external=True),
        'client_id': client_id,
        'client_secret': client_secret,
    }

    token_response = requests.post(token_url, data=token_data)
    token_response_data = token_response.json()

    if 'access_token' not in token_response_data:
        return "Failed to retrieve access token.", 400

    access_token = token_response_data['access_token']

    # 使用访问令牌获取用户信息
    headers = {'Authorization': f'Bearer {access_token}'}
    user_info_response = requests.get(user_info_url, headers=headers)
    user_info = user_info_response.json()

    user_id = user_info.get('id')
    username = user_info.get('username')
    trust_level = user_info.get('trust_level')

    # 将用户信息保存到 session
    session['user'] = {
        'id': user_id,
        'username': username,
        'trust_level': trust_level
    }

    # 检查用户是否已存在
    user = User.query.get(user_id)
    if user is None:
        # 如果用户不存在，则创建新用户
        user = User(id=user_id, username=username, trust_level=trust_level)
        db.session.add(user)
    else:
        # 如果用户已存在，则更新信息
        user.username = username
        user.trust_level = trust_level

    try:
        db.session.commit()  # 提交更改
    except Exception as e:
        print(f"Error committing to the database: {e}")  # 错误调试信息

    # 重定向到主页面
    return redirect(url_for('index'))

# 创建邮箱的主页面
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user' not in session:
        # 如果用户未登录，显示一个提示，而不是直接跳转到 OAuth 页面
        flash("请先登录以创建邮箱。")
        return render_template('index.html', today_email_count=None, max_daily_email_limit=None)

    # 获取当前登录的用户
    user = User.query.get(session['user']['id'])

    # 获取今天的日期
    today = datetime.utcnow().date()

    # 查询今天创建的邮箱数量
    today_email_count = Email.query.filter(
        Email.user_id == user.id,
        Email.created_at >= today
    ).count()

    # 设定每日创建邮箱最大数量，默认为1

max_daily_email_limit = int(os.getenv("MAX_DAILY_EMAIL_LIMIT"))

    if today_email_count >= max_daily_email_limit:
        flash(f'您今天已经创建了 {today_email_count} 个邮箱，达到每日创建上限 {max_daily_email_limit} 个。', 'warning')
        return render_template('index.html', today_email_count=today_email_count, max_daily_email_limit=max_daily_email_limit)

    if request.method == 'POST':
        email_username = request.form['username']
        email_password = request.form['password']
        domain = request.form['domain']  # 获取用户选择的域名

        # 检查数据库中是否已经存在相同的邮箱
        email_address = f"{email_username}{domain}"
        existing_email = Email.query.filter_by(email_address=email_address).first()

        if existing_email:
            flash('当前邮箱已存在，请选择其他邮箱名称。')
            return redirect(url_for('index'))

account_info = {
    "username": os.getenv("USERNAME"),
    "password": os.getenv("PASSWORD"),
    "panel": os.getenv("PANEL")
}

        result = login_and_create_email(account_info, email_username, email_password, domain)
        if result["success"]:
            new_email = Email(email_address=result['email'], password=result['password'], user_id=user.id)
            db.session.add(new_email)
            db.session.commit()
            flash(f'邮箱 {new_email.email_address} 创建成功！', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'邮箱创建失败: {result["message"]}', 'danger')

    return render_template('index.html', today_email_count=today_email_count, max_daily_email_limit=max_daily_email_limit)

# 登录处理
@app.route('/login')
def login():
    # 重定向到 OAuth 授权页面
    clientId = client_id
    redirectUri = url_for('oauth_callback', _external=True)
    authUrl = f"https://connect.linux.do/oauth2/authorize?client_id={clientId}&response_type=code&redirect_uri={redirectUri}"
    return redirect(authUrl)

import logging

@app.route('/user_center')
def user_center():
    if 'user' not in session:
        return redirect(url_for('login'))

    # 获取最新的用户信息和邮箱数据
    user = User.query.get(session['user']['id'])
    emails = Email.query.filter_by(user_id=user.id).all()

    # 添加调试信息
    print(f"User: {user.username}, Emails: {[email.email_address for email in emails]}")

    return render_template('user_center.html', user=user, emails=emails)


@app.route('/logout')
def logout():
    session.pop('user', None)  # 移除会话中的用户信息
    session.pop('email_username', None)
    session.pop('email_password', None)
    return redirect(url_for('index'))

# 邮箱创建逻辑
def login_and_create_email(account, email_username, email_password, domain):
    session = requests.Session()
    user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    login_url = f"https://{account['panel']}/login/?next=/mail/add"
    email_creation_url = f"https://{account['panel']}/mail/add"

    try:
        # 获取登录页面和CSRF token
        login_page = session.get(login_url, headers={"User-Agent": user_agent})
        soup = BeautifulSoup(login_page.content, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

        # 提交登录表单
        login_data = {
            'username': account['username'],
            'password': account['password'],
            'csrfmiddlewaretoken': csrf_token,
            'next': '/mail/add'
        }
        login_response = session.post(login_url, data=login_data, headers={
            "User-Agent": user_agent,
            "Referer": login_url,
            "Content-Type": "application/x-www-form-urlencoded"
        })

        # 创建邮箱
        if "Dodaj nowy adres e-mail" in login_response.text or "/mail/add" in login_response.url:
            mail_add_page = session.get(email_creation_url, headers={"User-Agent": user_agent})
            soup = BeautifulSoup(mail_add_page.content, 'html.parser')
            new_csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

            email = f"{email_username}{domain}"

            email_data = {
                'csrfmiddlewaretoken': new_csrf_token,
                'email': email,
                'password1': email_password,
                'password2': email_password
            }

            email_creation_response = session.post(email_creation_url, data=email_data, headers={
                "User-Agent": user_agent,
                "Referer": email_creation_url,
                "Content-Type": "application/x-www-form-urlencoded"
            })

            if email_creation_response.status_code == 200:
                return {"success": True, "email": email, "password": email_password}
            else:
                raise Exception("邮箱创建失败")
        else:
            raise Exception("登录失败")

    except Exception as e:
        return {"success": False, "message": str(e)}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 创建表
    app.run(debug=True)
