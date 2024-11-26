from flask import Flask, request, render_template, redirect, url_for, flash, session
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr
import boto3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # จำเป็นต้องมี secret key สำหรับ flash messages

# AWS Cognito Configuration
USER_POOL_ID = 'us-east-1_TO6EORboO'
APP_CLIENT_ID = '4p535l80p9dt798qq9q168709o'
cognito = boto3.client('cognito-idp', region_name='us-east-1')

# DynamoDB Configuration
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
EquipmentTable = dynamodb.Table('Equipment')

@app.route('/home', endpoint='home')
def main_page():
    return render_template('home.html')

@app.route('/equipment', endpoint='equipment')
def equipment_page():
    return render_template('equipment.html')

@app.route('/profile', endpoint='profile')
def profile_page():
    username = session.get('username')
    access_token = session.get('access_token')
    if not username or not access_token:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))
    try:
        response = cognito.get_user(
            AccessToken=access_token
        )
        user_attributes = {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
        user_info = {
            'username': username,
            'email': user_attributes.get('email'),
            'fullname': user_attributes.get('name'),
            'phone': user_attributes.get('phone_number'),
            'faculty': user_attributes.get('custom:faculty'),
            'student_id': user_attributes.get('custom:student_id'),
            'club_member': user_attributes.get('custom:club_member'),
            'dob': user_attributes.get('custom:dob')
        }
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Error: {error_message}")
        flash(error_message, 'error')
        return redirect(url_for('login'))

    return render_template('profile.html', user_info=user_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session and 'access_token' in session:
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # เรียกใช้งาน Cognito เพื่อเข้าสู่ระบบ
            response = cognito.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                },
                ClientId=APP_CLIENT_ID
            )

             # ตรวจสอบว่ามี ChallengeName หรือไม่
            if 'ChallengeName' in response and response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                session['username'] = username
                session['session'] = response['Session']
                flash('You need to change your password.', 'info')
                return redirect(url_for('change_password'))
            
            # ถ้าสำเร็จ ให้เก็บ Access Token หรือดำเนินการต่อ
            access_token = response['AuthenticationResult']['AccessToken']
            session['username'] = username
            session['access_token'] = access_token

            # ดึงข้อมูลผู้ใช้จาก Cognito
            user_response = cognito.get_user(
                AccessToken=access_token
            )
            user_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}
            role = user_attributes.get('custom:role')

            # ตรวจสอบว่าเป็นแอดมินหรือไม่
            if role == 'admin':
                flash('Login successful as admin!', 'success')
                return redirect(url_for('admin_req'))
            else:
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))

        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session or 'session' not in session:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']

        try:
            # เรียกใช้งาน Cognito เพื่อเปลี่ยนรหัสผ่าน
            response = cognito.respond_to_auth_challenge(
                ClientId=APP_CLIENT_ID,
                ChallengeName='NEW_PASSWORD_REQUIRED',
                Session=session['session'],
                ChallengeResponses={
                    'USERNAME': session['username'],
                    'NEW_PASSWORD': new_password
                }
            )

            # ถ้าสำเร็จ ให้เก็บ Access Token หรือดำเนินการต่อ
            access_token = response['AuthenticationResult']['AccessToken']
            session.clear()  # ล้างข้อมูลใน session
            flash('Password changed successfully!', 'success')
            return redirect(url_for('login'))

        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('change_password'))

    return render_template('change_password.html')

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
                    {'Name': 'custom:role', 'Value': 'user'}
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

@app.route('/logout')
def logout():
    session.clear()
    #flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/details_camera')
def details_camera():
    response = EquipmentTable.scan(
        FilterExpression=Attr('Category').eq('Camera')
    )
    items = response['Items']
    print(items)
    return render_template('detailscamera.html',items=items)

@app.route('/details_accessories')
def details_accessories():
    return render_template('detailsaccessories.html')

@app.route('/details_lenses')
def details_lenses():
    return render_template('detailslenses.html')

@app.route('/list')
def list():
    return render_template('list.html')

@app.route('/admin_req')
def admin_req():
    return render_template('admin_req.html')

@app.route('/admin_list')
def admin_list():
    return render_template('admin_list.html')

@app.route('/admin_lenses')
def admin_lenses():
    return render_template('admin_lenses.html')

@app.route('/admin_equipment')
def admin_equipment():
    return render_template('admin_equipment.html')

@app.route('/admin_accessories')
def admin_accessories():
    return render_template('admin_accessories.html')

@app.route('/admin_camera')
def admin_camera():
    return render_template('admin_camera.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
