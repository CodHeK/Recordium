from __future__ import print_function
from flask import Flask, render_template, redirect, url_for, session,request, make_response, current_app
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField,IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer,SignatureExpired,BadTimeSignature
import sqlite3 as sql
import hashlib
import datetime, time, random
import string
import os
from pytz import utc
from apscheduler.schedulers.background import BackgroundScheduler
import logging
logging.basicConfig()

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = "thisisasecretkey"
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://////home/mantek/Downloads/Recordium/soe.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://////Users/codhek/SOE/Recordium/soe.db'
app.jinja_env.add_extension('jinja2.ext.loopcontrols')
db = SQLAlchemy(app)
app.config.from_pyfile('config.cfg')
mail=Mail(app)
s=URLSafeTimedSerializer(app.config['SECRET_KEY'])


isscheduled=[0 for i in range(15)]
#########################
#TABLES

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    email = db.Column(db.String(30))
    institute = db.Column(db.String(30))
    semester = db.Column(db.String(30))
    type = db.Column(db.String(20))
    password = db.Column(db.String(80))
    confirm_email=db.Column(db.Boolean)

class Requests(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    professor_id=db.Column(db.String(15))
    class_duration=db.Column(db.Integer)
    semester=db.Column(db.String(20))
    subject_code=db.Column(db.String(15))
    status=db.Column(db.Integer)
    institute=db.Column(db.String(30))
    class_type = db.Column(db.String(15))

class TimeTable(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    semester = db.Column(db.String(30))
    day = db.Column(db.String(30))
    start = db.Column(db.String(30))
    end = db.Column(db.String(20))
    subject_code = db.Column(db.String(80))
    professor_id = db.Column(db.String(15))
    class_type = db.Column(db.String(15))


class IsScheduled(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    semester = db.Column(db.String(30))


class Subscribe(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    subject_code = db.Column(db.String(15))
    user_id = db.Column(db.String(15))
    day = db.Column(db.String(15))
    start = db.Column(db.String(15))


#########################


#########################
#FORMS

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    institute = StringField('Institute', validators=[InputRequired(), Length(min=0, max=100)])
    semester = SelectField('Semester', choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'), ('7', '7'), ('8', '8'), ('nil', 'nil')], validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=90)])
    type = SelectField('Type', choices=[('student', 'student'), ('faculty', 'faculty')], validators=[InputRequired()])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=90)])

class FacultyRequestForm(FlaskForm):
    subject_code=StringField('Enter Subject Code',validators=[InputRequired(), Length(min=4, max=15)])
    class_duration= SelectField('Enter Class duration in hours',validators=[InputRequired()], choices=[('1', '1'), ('2', '2'),('3','3')])
    semester = SelectField('Semester', choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'), ('7', '7'), ('8', '8'), ('nil', 'nil')], validators=[InputRequired()])
    class_type = SelectField('Select Class type',validators=[InputRequired()], choices=[('1', 'Theory'), ('2', 'Lab')])

class GetAdminEmailForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])

class SemFilterForm(FlaskForm):
    semester = SelectField('Semester', choices=[('all', 'all'), ('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'), ('7', '7'), ('8', '8')], validators=[InputRequired()])

class GetSemesterForSchedule(FlaskForm):
    semester = SelectField('Semester', choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'), ('7', '7'), ('8', '8')], validators=[InputRequired()])

class GetSubjs(FlaskForm):
    subjects = SelectField('Subjects', choices=[], validators=[InputRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[InputRequired(), Length(min=6, max=90)])
    new_password = PasswordField('New Password', validators=[InputRequired(), Length(min=6, max=90)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[InputRequired(), Length(min=6, max=90)])

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
#########################


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        type = form.type.data
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            message = "** email already exists"
            return render_template('signup.html', message=message, form=form)
        else:
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, type=form.type.data, confirm_email=False, institute=form.institute.data, semester=form.semester.data)
            email = form.email.data
            token=s.dumps(email,salt='email-confirm')
            msg=Message('Confirm mail',sender='iit2016007@iiita.ac.in',recipients=[email])
            link=url_for('confirm_email',token=token,types=form.type.data,_external=True)
            msg.body='Your link is {}'.format(link)
            mail.send(msg)
            db.session.add(new_user)
            db.session.commit()
            message = "confirm your email to login"
            return render_template('login.html', message=message, form=form)
    return render_template('signup.html', form=form)





@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                if user.confirm_email == 1:
                    session['id'] = user.id
                    session['username'] = user.username
                    session['email'] = user.email
                    session['type'] = user.type
                    session['institute'] = user.institute
                    session['semester'] = user.semester
                    if user.type == 'student':
                        return redirect(url_for('dashboard_student'))
                    elif user.type == 'faculty':
                        return redirect(url_for('dashboard_faculty'))
                    else:
                        return redirect(url_for('dashboard_admin'))
                else:
                    return render_template('login.html', form=form, message="** Please verify your email!")
            return render_template('login.html', form=form, message="** email or password for client doesn't seem right!")
        else:
            return render_template('login.html', form=form, message="** email doesn't seem right!")
    return render_template('login.html', form=form)


#########################################
@app.route('/confirm_email/<token>/<types>')
def confirm_email(token,types):
    try:
        email=s.loads(token,salt='email-confirm')
        user=User.query.filter_by(email=email,type=types).first()
        user.confirm_email=True
        db.session.commit()
    except SignatureExpired:
        #'The token is expired!'
        #message='expired'
        return redirect(url_for('signup'),message="time up")
    except BadTimeSignature:
        #'The token is expired!'
        #message='expired'
        return redirect(url_for('signup'),message="** bad signature detected. **")
    return redirect(url_for('login'))






@app.route('/dashboard/student', methods=['GET', 'POST'])
def dashboard_student():
    if 'username' in session and session['type'] == 'student':
        session_username = session['username']
        session_username = session_username[0].upper() + session_username[1:]
        getSem = User.query.filter_by(id=session["id"]).first()
        sem = getSem.semester
        check_exists = IsScheduled.query.filter_by(semester=sem).first()
        # print(sem)
        timetable = [[None for j in range(4)] for i in range(5)]
        tt = []
        if check_exists:
            getRows = TimeTable.query.filter_by(semester=sem,class_type="1").all()
            labs = TimeTable.query.filter_by(semester=sem,class_type="2").all()
            row = 0
            col = 0
            for eachRow in getRows:
                if eachRow.subject_code == "free":
                    timetable[row][col] = None
                else:
                    timetable[row][col] = eachRow
                print(timetable[row][col])
                col += 1
                if col == 4:
                    col = 0
                    row += 1
                    print("\n")

            for i in range(5):
                row = []
                if i == 0:
                    data = {
                        'subject': "Monday",
                        'prof': ""
                    }
                elif i == 1:
                    data = {
                        'subject': "Tuesday",
                        'prof': ""
                    }
                elif i == 2:
                    data = {
                        'subject': "Wednesday",
                        'prof': ""
                    }
                elif i == 3:
                    data = {
                        'subject': "Thurday",
                        'prof': ""
                    }
                elif i == 4:
                    data = {
                        'subject': "Friday",
                        'prof': ""
                    }
                row.append(data)
                for j in range(4):
                    if timetable[i][j] != None:
                        prof = User.query.filter_by(id=timetable[i][j].professor_id).first()
                        data = {
                            'subject': timetable[i][j].subject_code,
                            'prof': prof.username
                        }
                        row.append(data)
                    else:
                        data = {
                            'subject': "-",
                            'prof': ""
                        }
                        row.append(data)
                tt.append(row)

            for i in range(5):
                data = {}
                if(i>= len(labs)):
                    data = {
                        'subject': "-",
                        'prof': ""
                    }
                else:
                    prof = User.query.filter_by(id=labs[i].professor_id).first()
                    data = {
                        'subject': labs[i].subject_code,
                        'prof': prof.username
                    }
                tt[i].append(data)
                #print(tt)
            return render_template('dashboard_student.html', session_username=session_username, timetable=tt, flag=0)
        else:
            message = "Your time-table has not been scheduled yet!"
            return render_template('dashboard_student.html', session_username=session_username, timetable=tt, flag=1,  message=message)
    else:
        session_type = session['type']
        return render_template('not_logged_in.html',session_type=session_type)

@app.route('/dashboard/faculty', methods=['GET', 'POST'])
def dashboard_faculty():
    if 'username' in session and session['type'] == 'faculty':
        timetable = [[None for j in range(4)] for i in range(5)]
        session_username = session['username']
        session_username = session_username[0].upper() + session_username[1:]
        row = 0
        col = 0
        for i in range(5):
            getRows = TimeTable.query.filter_by(professor_id=session["id"],day=str(i),class_type="1").all()
            for eachRow in getRows:
                timetable[i][int(eachRow.start)] = eachRow
        tt = []
        for i in range(5):
            row = []
            if i == 0:
                data = {
                    'subject': "Monday",
                    'prof': ""
                }
            elif i == 1:
                data = {
                    'subject': "Tuesday",
                    'prof': ""
                }
            elif i == 2:
                data = {
                    'subject': "Wednesday",
                    'prof': ""
                }
            elif i == 3:
                data = {
                    'subject': "Thurday",
                    'prof': ""
                }
            elif i == 4:
                data = {
                    'subject': "Friday",
                    'prof': ""
                }
            row.append(data)
            for j in range(4):
                if timetable[i][j] != None:
                    # prof = User.query.filter_by(id=timetable[i][j].semester).first()
                    data = {
                        'subject': timetable[i][j].subject_code,
                        'prof': "sem " + timetable[i][j].semester
                    }
                    row.append(data)
                else:
                    data = {
                        'subject': "-",
                        'prof': ""
                    }
                    row.append(data)
            tt.append(row)

        for i in range(5):
            data = {}
            labs = TimeTable.query.filter_by(professor_id=session["id"],day=str(i),class_type="2").first()
            if labs:
                data = {
                    'subject': labs.subject_code,
                    'prof': "Sem " + labs.semester
                }
            else:
                data = {
                    'subject': "-",
                    'prof': ""
                }

            tt[i].append(data)
        check_if_admin_exists = User.query.filter_by(institute=session['institute'], type='admin').first()
        if check_if_admin_exists:
            return render_template('dashboard_faculty.html', session_username=session_username, exists=1, timetable = tt)
        else:
            return render_template('dashboard_faculty.html', session_username=session_username, exists=0, timetable = tt)
    else:
        session_type = session['type']
        return render_template('not_logged_in.html',session_type=session_type)

@app.route('/dashboard/admin', methods=['GET', 'POST'])
def dashboard_admin():
    form = SemFilterForm()
    if 'username' in session and session['type'] == 'admin':
        session_username = session['username']
        session_username = session_username[0].upper() + session_username[1:]
        requests = Requests.query.filter_by(institute=session['institute'], status=0).all()
        length = len(requests)
        if form.validate_on_submit():
            getSem = form.semester.data
            if getSem != 'all':
                getRequests = Requests.query.filter_by(institute=session['institute'], semester=getSem).all()
                length = len(getRequests)
                return render_template('dashboard_admin.html', session_username=session_username, requests=getRequests, length=length, form=form)
            else:
                requests = Requests.query.filter_by(institute=session['institute'], status=0).all()
                length = len(requests)
                return render_template('dashboard_admin.html', session_username=session_username, requests=requests, length=length, form=form)
        return render_template('dashboard_admin.html', session_username=session_username, requests=requests, length=length, form=form)
    else:
        session_type = session['type']
        return render_template('not_logged_in.html',session_type=session_type)

###################################
@app.route('/dashboard/faculty/newrequest', methods=['GET', 'POST'])
def new_request_faculty():
    form=FacultyRequestForm()
    session_username=session['username']
    session_username=session_username[0].upper() + session_username[1:]
    if form.validate_on_submit():
        new_request=Requests(subject_code=form.subject_code.data,class_duration=form.class_duration.data,professor_id=session['id'],semester=form.semester.data,status=0, institute=session['institute'],class_type=form.class_type.data)
        db.session.add(new_request)
        db.session.commit()
        message="** request successfully added **"
        return render_template('faculty_request.html', message=message, form=form, session_username=session_username)
    return render_template('faculty_request.html',session_username=session_username,form=form)

@app.route('/requests', methods=['GET', 'POST'])
def see_all_requests():
    requests = Requests.query.filter_by(professor_id=session['id']).order_by(desc(Requests.id))
    session_username=session['username']
    session_username=session_username[0].upper() + session_username[1:]
    return render_template('see_all_requests.html', requests=requests, session_username=session_username)

@app.route('/request/accepted/<int:request_id>', methods=['GET', 'POST'])
def accept_request(request_id):
    get_that_request = Requests.query.filter_by(id=request_id).first()
    get_that_request.status = 1;
    db.session.commit();
    return redirect(url_for('dashboard_admin'))

@app.route('/request/declined/<int:request_id>', methods=['GET', 'POST'])
def decline_request(request_id):
    get_that_request = Requests.query.filter_by(id=request_id).first()
    get_that_request.status = -1;
    db.session.commit();
    return redirect(url_for('dashboard_admin'))


@app.route('/generate_admin', methods=['GET', 'POST'])
def generate_admin():
    form = GetAdminEmailForm()
    session_username=session['username']
    session_username=session_username[0].upper() + session_username[1:]
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.email.data, method='sha256')
        email = form.email.data
        email_start = email.split('@')[0]
        password = email_start + hashed_password[5:10]
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, type='admin', confirm_email=True, institute=session['institute'], semester='nil')
        token=s.dumps(email, salt='email-confirm')
        msg=Message('Admin Credentials',sender='iit2016007@iiita.ac.in',recipients=[email])
        msg.body='Your Login password: {}'.format(password)
        mail.send(msg)
        db.session.add(new_user)
        db.session.commit()
        message = "Admin successfully created ! Login Credentials for admin sent to admin emailID"
        return render_template('generate_admin.html', message=message, form=form, session_username=session_username,  institute=session['institute'])
    return render_template('generate_admin.html', form=form, session_username=session_username, institute=session['institute'])



####################################################
def noclash(cur_day, cur_slot,one,dur):
    if dur==1:
        exists = TimeTable.query.filter_by(day=cur_day,start=cur_slot, professor_id=one.professor_id,class_type="1").all()
        if len(exists)==0:
            return True
        return False
    else:
        exists1 = TimeTable.query.filter_by(day=cur_day,start=cur_slot, end=cur_slot+1,professor_id=one.professor_id,class_type="1").all()
        exists2 = TimeTable.query.filter_by(day=cur_day,start=cur_slot, end=cur_slot,professor_id=one.professor_id,class_type="1").all()
        exists3 = TimeTable.query.filter_by(day=cur_day,start=cur_slot+1, end=cur_slot+1,professor_id=one.professor_id,class_type="1").all()
        if len(exists1)==0 and len(exists2)==0 and len(exists3)==0:
            return True
        return False


def rec(timetable, cur_day, cur_slot, ones, twos, len1, len2):
    if len1 == 0 and len2 == 0:
        return True
    if cur_day == 5:
        return False
    if cur_slot == 4:
        cur_day += 1
        if cur_day == 5:
            return False
        cur_slot = 0
    ind_ar = [0,1,2]
    random.shuffle(ind_ar)
    for index in ind_ar:

        if index == 0:
            ind = -1
            for i in range(len1):
                if noclash(cur_day,cur_slot,ones[i],1)==True:
                    ind=i
                    break
            if ind>=0:
                timetable[cur_day][cur_slot] = ones[ind]
                ones[ind], ones[len1-1] = ones[len1-1], ones[ind]

                if rec(timetable, cur_day, cur_slot+1, ones, twos, len1-1, len2)==True:
                    return True
                timetable[cur_day][cur_slot] = None
                ones[ind], ones[len1-1] = ones[len1-1], ones[ind]
        if index == 1:
            if cur_slot < 3:
                ind=-1
                for i in range(len2):
                    if noclash(cur_day,cur_slot,twos[i],2)==True:
                        ind=i
                        break
                if ind>=0:
                    timetable[cur_day][cur_slot] = twos[ind]
                    timetable[cur_day][cur_slot+1] = twos[ind]
                    twos[ind], twos[len2-1] = twos[len2-1], twos[ind]

                    if rec(timetable, cur_day, cur_slot+2, ones, twos, len1, len2-1)==True:
                        return True
                    timetable[cur_day][cur_slot] = None
                    timetable[cur_day][cur_slot+1] = None
                    twos[ind], twos[len2-1] = twos[len2-1], twos[ind]
        if index == 2:
            if rec(timetable, cur_day, cur_slot+1, ones, twos, len1, len2)==True:
                return True
    return False
######################################################


@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    form = GetSemesterForSchedule()
    session_username=session['username']
    session_username=session_username[0].upper() + session_username[1:]
    if form.validate_on_submit():
        is_sch = IsScheduled.query.filter_by(semester=form.semester.data).first()
        requests = Requests.query.filter_by(semester=form.semester.data, status=1,class_type="1").all()
        if len(requests) == 0:
            message = "No requests available"
            return render_template('scheduling.html', form=form, session_username=session_username, message=message)
        else:
            sem=form.semester.data
            ones = Requests.query.filter_by(semester=form.semester.data, class_duration=1, status=1,class_type="1").all()
            twos = Requests.query.filter_by(semester=form.semester.data, class_duration=2, status=1,class_type="1").all()
            timetable = [[None for j in range(4)] for i in range(5)]
            len1 = len(ones)
            len2 = len(twos)
            if is_sch:
                db.session.delete(is_sch)
                db.session.commit()
                from_time_table = TimeTable.query.filter_by(semester=form.semester.data).all()
                for each in from_time_table:
                    db.session.delete(each)
                    db.session.commit()
            if rec(timetable, 0, 0, ones, twos, len1, len2) == False:
                message = "Time table cannot be scheduled"
                return render_template('scheduling.html', form=form, session_username=session_username, message=message)
            else:
                labs = Requests.query.filter_by(semester=form.semester.data, status=1,class_type="2").all()
                if(len(labs)>5):
                   message = "Time table cannot be scheduled"
                   return render_template('scheduling.html', form=form, session_username=session_username, message=message)
                else:
                   for i in range(len(labs)):
                       new_time_table = TimeTable(semester=form.semester.data, day=str(i), subject_code=labs[i].subject_code, professor_id=labs[i].professor_id,class_type="2")
                       db.session.add(new_time_table)
                       db.session.commit()
                for i in range(5):
                    for j in range(4):
                        if timetable[i][j] != None:
                            dur = timetable[i][j].class_duration
                            if dur == 1:
                                new_time_table = TimeTable(semester=form.semester.data, day=str(i), start=str(j), end=str(j), subject_code=timetable[i][j].subject_code, professor_id=timetable[i][j].professor_id,class_type="1")
                            else:
                                new_time_table = TimeTable(semester=form.semester.data, day=str(i), start=str(j), end=str(j+1), subject_code=timetable[i][j].subject_code, professor_id=timetable[i][j].professor_id,class_type="1")
                        else:
                            new_time_table = TimeTable(semester=form.semester.data, day=str(i), start=str(j), end=str(j), subject_code="free", professor_id="",class_type="1")
                        db.session.add(new_time_table)
                        db.session.commit()
                new_sem_scheduled = IsScheduled(semester = form.semester.data);
                db.session.add(new_sem_scheduled)
                db.session.commit()

                tt = []
                for i in range(5):
                    row = []
                    if i == 0:
                        data = {
                            'subject': "Monday",
                            'prof': ""
                        }
                    elif i == 1:
                        data = {
                            'subject': "Tuesday",
                            'prof': ""
                        }
                    elif i == 2:
                        data = {
                            'subject': "Wednesday",
                            'prof': ""
                        }
                    elif i == 3:
                        data = {
                            'subject': "Thurday",
                            'prof': ""
                        }
                    elif i == 4:
                        data = {
                            'subject': "Friday",
                            'prof': ""
                        }
                    row.append(data)
                    for j in range(4):
                        if timetable[i][j] != None:
                            prof = User.query.filter_by(id=timetable[i][j].professor_id).first()
                            data = {
                                'subject': timetable[i][j].subject_code,
                                'prof': prof.username
                            }
                            row.append(data)
                        else:
                            data = {
                                'subject': "-",
                                'prof': ""
                            }
                            row.append(data)
                    tt.append(row)
                for i in range(5):
                    data = {}
                    if(i>= len(labs)):
                        data = {
                            'subject': "-",
                            'prof': ""
                        }
                    else:
                        prof = User.query.filter_by(id=labs[i].professor_id).first()
                        data = {
                            'subject': labs[i].subject_code,
                            'prof': prof.username
                        }
                    tt[i].append(data)

                message = "Time table scheduled"
                # print(tt)
                return render_template('scheduling.html', form=form, session_username=session_username, message=message, timetable=tt)
    return render_template('scheduling.html', form=form,  session_username=session_username)


###########################################################

@app.route('/change_password',methods=['GET','POST'])
def change_password():
    email = session['email']
    session_username=session['username']
    session_username=session_username[0].upper() + session_username[1:]
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=session['email']).first()
        if check_password_hash(user.password, form.current_password.data):
            new_password=form.new_password.data
            confirm_new_password=form.confirm_new_password.data
            if new_password==confirm_new_password:
                hashed_password = generate_password_hash(form.new_password.data, method='sha256')
                user.password=hashed_password
                db.session.commit()
                message="Password has been successfully changed!"
                return render_template('change_password.html', session_username=session_username,form=form,message=message)
            else:
                message="The new Password and confirm new password fields are not equal"
                return render_template('change_password.html', session_username=session_username,form=form,message=message)
        else:
            message="Password entered is incorrect"
            return render_template('change_password.html', session_username=session_username,form=form,message=message)

    return render_template('change_password.html',session_username=session_username, form=form)



@app.route('/subscribe',methods=['GET','POST'])
def subscribe():
    form = GetSubjs()
    session_username=session['username']
    session_username=session_username[0].upper() + session_username[1:]
    getSubjects = TimeTable.query.filter_by(professor_id=session["id"]).all()
    subjs = []
    for subs in getSubjects:
        if (subs.subject_code, subs.subject_code) not in subjs:
            subjs.append((subs.subject_code, subs.subject_code))
    form.subjects.choices = subjs
    if form.validate_on_submit():
        subj = form.subjects.data
        getDays = TimeTable.query.filter_by(subject_code=subj, class_type="1").all()
        getLabDays = TimeTable.query.filter_by(subject_code=subj, class_type="2").all()
        reminder = []
        is_exist = Subscribe.query.filter_by(user_id=session["id"], subject_code=subj).all()
        if len(is_exist) == 0:
            for each in getDays:
                dur = int(each.end) - int(each.start) + 1
                data = {
                    'dur': dur,
                    'subj_code': each.subject_code
                }
                if data not in reminder:
                    reminder.append(data)
                    startTime = ""
                    if each.start == "0":
                        startTime = "8:45"
                    if each.start == "1":
                        startTime = "9:45"
                    if each.start == "2":
                        startTime = "11:00"
                    if each.start == "3":
                        startTime = "12:00"
                    new_subcription = Subscribe(user_id=session["id"], subject_code=subj, day=each.day, start=startTime)
                    db.session.add(new_subcription)
                    db.session.commit()

            for eachLab in getLabDays:
                new_subcription = Subscribe(user_id=session["id"], subject_code=eachLab.subject_code, day=eachLab.day, start="2:45")
                db.session.add(new_subcription)
                db.session.commit()
            message = subj + " subscribed !"
            return render_template('subscribe.html', form=form, session_username=session_username, message=message, flag=1)
        else:
            message = subj + " already subscribed !"
            return render_template('subscribe.html', form=form, session_username=session_username, message=message, flag=0)
    return render_template('subscribe.html', form=form, session_username=session_username)


@app.route('/subscribe_student',methods=['GET','POST'])
def subscribe_student():
    form = GetSubjs()
    session_username=session['username']
    session_username=session_username[0].upper() + session_username[1:]
    getUser = User.query.filter_by(id=session["id"]).first()
    getSubjects = TimeTable.query.filter_by(semester=getUser.semester).all()
    subjs = []
    for subs in getSubjects:
        if (subs.subject_code, subs.subject_code) not in subjs and subs.subject_code!="free":
            subjs.append((subs.subject_code, subs.subject_code))
    form.subjects.choices = subjs
    if form.validate_on_submit():
        subj = form.subjects.data
        getDays = TimeTable.query.filter_by(subject_code=subj, class_type="1",semester=getUser.semester).all()
        getLabDays = TimeTable.query.filter_by(subject_code=subj, class_type="2",semester=getUser.semester).all()
        reminder = []
        is_exist = Subscribe.query.filter_by(user_id=session["id"], subject_code=subj).all()
        if len(is_exist) == 0:
            for each in getDays:
                print(each.subject_code)
                dur = int(each.end) - int(each.start) + 1
                data = {
                    'dur': dur,
                    'subj_code': each.subject_code
                }
                if data not in reminder:
                    reminder.append(data)
                    startTime = ""
                    if each.start == "0":
                        startTime = "8:45"
                    if each.start == "1":
                        startTime = "9:45"
                    if each.start == "2":
                        startTime = "11:00"
                    if each.start == "3":
                        startTime = "12:00"
                    new_subcription = Subscribe(user_id=session["id"], subject_code=subj, day=each.day, start=startTime)
                    db.session.add(new_subcription)
                    db.session.commit()

            for eachLab in getLabDays:
                new_subcription = Subscribe(user_id=session["id"], subject_code=eachLab.subject_code, day=eachLab.day, start="2:45")
                db.session.add(new_subcription)
                db.session.commit()
            message = subj + " subscribed !"
            return render_template('subscribe_student.html', form=form, session_username=session_username, message=message, flag=1)
        else:
            message = subj + " already subscribed !"
            return render_template('subscribe_student.html', form=form, session_username=session_username, message=message, flag=0)
    return render_template('subscribe_student.html', form=form, session_username=session_username)



###########################################################

@app.route('/take_back')
def take_back():
    type=session['type']
    if type == 'student':
        return redirect(url_for('dashboard_student'))
    elif type == 'faculty':
        return redirect(url_for('dashboard_faculty'))
    else:
        return redirect(url_for('dashboard_admin'))


#####################################


@app.route('/forgot_password',methods=['GET','POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email=form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token=''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
            msg=Message('Forgot Password mail',sender='iit2016007@iiita.ac.in',recipients=[email])
            msg.body='Login using your temporary password {}'.format(token)
            hashed_password = generate_password_hash(token, method='sha256')
            user.password=hashed_password
            db.session.commit()
            mail.send(msg)
            message="We have sent you a temprary password. Please login using that"
            return render_template('forgot_password.html', form=form,message=message)
        else:
            message="No user with this email exists"
            return render_template('forgot_password.html', form=form,message=message)
    return render_template('forgot_password.html', form=form)



####################################
@app.route('/logout')
# @login_required
def logout():
    if 'type' in session:
        if session['type'] == 'student':
            session.pop('username', None)
            return redirect(url_for('index'))
        elif session['type'] == 'faculty':
            session.pop('username', None)
            return redirect(url_for('index'))
        elif session['type'] == 'admin':
            session.pop('username', None)
            return redirect(url_for('index'))

########################################
scheduler = BackgroundScheduler({
    'apscheduler.executors.default': {
    'class': 'apscheduler.executors.pool:ThreadPoolExecutor',
    'max_workers': '20'
    },
    'apscheduler.timezone': 'UTC',
})
def dayNameFromWeekday(weekday):
    if weekday == 0:
        return "Monday"
    if weekday == 1:
        return "Tuesday"
    if weekday == 2:
        return "Wednesday"
    if weekday == 3:
        return "Thursday"
    if weekday == 4:
        return "Friday"
    if weekday == 5:
        return "Saturday"
    if weekday == 6:
        return "Sunday"

from datetime import datetime

def perform845():
    getTime = Subscribe.query.filter_by(start="8:45").all()
    for each in getTime:
        current_date = datetime.now()
        cur_day = dayNameFromWeekday(int(each.day))
        if str(current_date.strftime('%A')) != cur_day:
            continue
        user_id = each.user_id
        getUser = User.query.filter_by(id=user_id).first()
        email = getUser.email
        msg=Message('Reminder',sender='iit2016007@iiita.ac.in',recipients=[email])
        msg.body = 'Subject: ' + each.subject_code + ' class is about to start in 15 minutes'
        with app.app_context():
            mail.send(msg)

def perform945():
    getTime = Subscribe.query.filter_by(start="9:45").all()
    for each in getTime:
        current_date = datetime.now()
        cur_day = dayNameFromWeekday(int(each.day))
        if str(current_date.strftime('%A')) != cur_day:
            continue
        user_id = each.user_id
        getUser = User.query.filter_by(id=user_id).first()
        email = getUser.email
        msg=Message('Reminder',sender='iit2016007@iiita.ac.in',recipients=[email])
        msg.body = 'Subject: ' + each.subject_code + ' class is about to start in 15 minutes'
        with app.app_context():
            mail.send(msg)

def perform1100():
    getTime = Subscribe.query.filter_by(start="11:00").all()
    for each in getTime:
        current_date = datetime.now()
        cur_day = dayNameFromWeekday(int(each.day))
        if str(current_date.strftime('%A')) != cur_day:
            continue
        user_id = each.user_id
        getUser = User.query.filter_by(id=user_id).first()
        email = getUser.email
        msg=Message('Reminder',sender='iit2016007@iiita.ac.in',recipients=[email])
        msg.body = 'Subject: ' + each.subject_code + ' class is about to start in 15 minutes'
        with app.app_context():
            mail.send(msg)

def perform1200():
    getTime = Subscribe.query.filter_by(start="12:00").all()
    for each in getTime:
        current_date = datetime.now()
        cur_day = dayNameFromWeekday(int(each.day))
        if str(current_date.strftime('%A')) != cur_day:
            continue
        user_id = each.user_id
        getUser = User.query.filter_by(id=user_id).first()
        email = getUser.email
        msg=Message('Reminder',sender='iit2016007@iiita.ac.in',recipients=[email])
        msg.body = 'Subject: ' + each.subject_code + ' class is about to start in 15 minutes'
        with app.app_context():
            mail.send(msg)

def perform1445():
    getTime = Subscribe.query.filter_by(start="2:45").all()
    for each in getTime:
        current_date = datetime.now()
        cur_day = dayNameFromWeekday(int(each.day))
        if str(current_date.strftime('%A')) != cur_day:
            continue8
        user_id = each.user_id
        getUser = User.query.filter_by(id=user_id).first()
        email = getUser.email
        msg=Message('Reminder',sender='iit2016007@iiita.ac.in',recipients=[email])
        msg.body = 'Subject: ' + each.subject_code + ' class is about to start in 15 minutes'
        with app.app_context():
            mail.send(msg)

scheduler.add_job(perform845, 'cron', day_of_week='mon-sun', hour=3, minute=15)
scheduler.add_job(perform945, 'cron', day_of_week='mon-sun', hour=4, minute=15)
scheduler.add_job(perform1100, 'cron', day_of_week='mon-sun', hour=5, minute=30)
scheduler.add_job(perform1200, 'cron', day_of_week='mon-sun', hour=6, minute=30)
scheduler.add_job(perform1445, 'cron', day_of_week='mon-sun', hour=9, minute=15)


if __name__ == '__main__':
    scheduler.start()
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True,port=5001)
    # scheduler = APScheduler()












































































#high coding standard
#my code is beautiful
