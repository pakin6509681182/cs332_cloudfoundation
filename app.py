from flask import Flask, request, render_template, redirect, url_for, flash
from botocore.exceptions import ClientError
import boto3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # จำเป็นต้องมี secret key สำหรับ flash messages

# AWS Cognito Configuration
USER_POOL_ID = 'us-east-1_TO6EORboO'
APP_CLIENT_ID = '4p535l80p9dt798qq9q168709o'
cognito = boto3.client('cognito-idp', region_name='us-east-1')

@app.route('/home', endpoint='home')
def main_page():
    return render_template('home.html')

@app.route('/equipment', endpoint='equipment')
def equipment_page():
    return render_template('equipment.html')

@app.route('/list', endpoint='list')
def list_page():
    return render_template('list.html')

@app.route('/profile', endpoint='profile')
def profile_page():
    return render_template('profile.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            # เรียกใช้งาน Cognito เพื่อเข้าสู่ระบบ
            response = cognito.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password
                },
                ClientId=APP_CLIENT_ID
            )

            # ถ้าสำเร็จ ให้เก็บ Access Token หรือดำเนินการต่อ
            access_token = response['AuthenticationResult']['AccessToken']
            flash('Login successful!', 'success')
            return redirect(url_for('login'))

        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # รับข้อมูลจาก Form
        fullname = request.form['fullname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        faculty = request.form['faculty']
        student_id = request.form['student-id']
        phone = request.form['phone']
        club_member = request.form['club-member']
        dob = request.form['dob']

        # ตรวจสอบรหัสผ่าน
        if password != confirm_password:
            return "Passwords do not match!", 400

        # สร้างผู้ใช้ใน Cognito
        try:
            response = cognito.sign_up(
                ClientId=APP_CLIENT_ID,
                Username=username,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'name', 'Value': fullname},
                    {'Name': 'phone_number', 'Value': phone},
                    {'Name': 'custom:faculty', 'Value': faculty},
                    {'Name': 'custom:student_id', 'Value': student_id},
                    {'Name': 'custom:club_member', 'Value': club_member},
                    {'Name': 'custom:dob', 'Value': dob},
                ]
            )
            flash('You have successfully signed up!', 'success')
            return redirect(url_for('signup'))
        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/signup-success')
def signup_success():
    return "Signup successful! Please verify your email."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)