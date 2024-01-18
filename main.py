from flask import Flask, render_template, redirect, url_for, flash, abort, request, session
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from forms import RegisterForm, LoginForm
import razorpay
import os
from dotenv import load_dotenv
from datetime import datetime as dt

########################################################################################################################
razor_key = os.environ.get("RAZOR_KEY")
razor_secret = os.environ.get("RAZOR_SECRET")

########################################################################################################################
# INITIALIZATION
load_dotenv()

app = Flask(__name__)
login_manager = LoginManager()
app.config['SECRET_KEY'] = os.environ.get("APP_SECRET")
login_manager.init_app(app)
Bootstrap(app)

########################################################################################################################
# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///Travel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    rfid = db.Column(db.String(250), nullable=True, unique=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    entries = relationship("Task", backref="passenger")


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    passenger_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    uid_1 = db.Column(db.String(250), unique=True, nullable=True)
    dec_1 = db.Column(db.String(250), nullable=True)

    uid_2 = db.Column(db.String(250), nullable=True)
    dec_2 = db.Column(db.String(250), nullable=True)

    distance = db.Column(db.Float, nullable=True)
    due = db.Column(db.String(250), nullable=True)

    initial_timestamp = db.Column(db.String(250), nullable=True)
    final_timestamp = db.Column(db.String(250), nullable=True)


class Stations(db.Model):
    __tablename__ = "stations"
    id = db.Column(db.Integer, primary_key=True)
    station_name = db.Column(db.String(250), unique=True, nullable=False)
    station_hexa = db.Column(db.String(250), unique=True, nullable=False)
    distance_from_initial = db.Column(db.Float, nullable=False)


class UserHistory(db.Model):
    __tablename__ = "user_history"
    id = db.Column(db.Integer, primary_key=True)
    card = db.Column(db.String(250), nullable=True)
    _from = db.Column(db.String(250), nullable=True)
    _to = db.Column(db.String(250), nullable=True)
    _from_time = db.Column(db.String(250), nullable=True)
    _to_time = db.Column(db.String(250), nullable=True)
    travel_distance = db.Column(db.Float, nullable=True)
    order_payment_id = db.Column(db.String(250), nullable=True)

    ticket_due = db.Column(db.Integer, nullable=True)


db.create_all()


########################################################################################################################
# ADMIN ONLY DECORATOR
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


########################################################################################################################

# USER LOADER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


########################################################################################################################
# HOME ROUTE
@app.route('/')
def home():
    return render_template('index.html', current_user=current_user)


########################################################################################################################
# ADMIN_ONLY_ROUTE
@app.route('/admin', methods=["GET", "POST"])
@admin_only
def admin():
    all_users = User.query.all()
    return render_template("admin.html", current_user=current_user, all_users=all_users)


@app.route('/user_details')
@admin_only
def show_details():
    id_for_details = request.args.get("user_detail_id")
    selected_user = User.query.get(id_for_details)
    return render_template('admin_profile.html', selected_user=selected_user)


# ADMIN_ONLY_DELETE_USER
@app.route('/admin/delete_user', methods=["GET", "POST"])
@admin_only
def delete_user():
    uid_to_delete = request.args.get('user_id_to_delete')
    user_to_delete = User.query.get(uid_to_delete)
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for("admin"))


# ADMIN_ONLY_ADD_USER_RFID
@app.route('/admin/add_rfid', methods=["GET", "POST"])
@admin_only
def add_user_rfid():
    new_user_id = request.args.get("user_id_for_rfid")
    if request.method == "POST":
        # print(request.form["rfid_value"])
        new_user_rfid = User.query.get(new_user_id)
        new_user_rfid.rfid = request.form["rfid_value"]
        db.session.commit()
        return redirect(url_for('admin'))


########################################################################################################################


# REGISTER
@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        name = register_form.name.data
        email = register_form.email.data
        password = register_form.password.data
        # rfid = register_form.user_rfid.data

        if User.query.filter_by(email=email).first():
            flash(f"User with email {email} is already registered, Please Login.")
            return redirect(url_for('login'))
        # elif User.query.filter_by(rfid=rfid).first():
        #     flash(f"User with RFID no. {rfid} is already registered, Please Login.")
        #     return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=10)
            new_user = User(
                email=email,
                password=hashed_password,
                # rfid=rfid,
                name=name,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        return redirect(url_for('home'))
    return render_template('REGISTER.html', form=register_form, current_user=current_user)


# LOGIN
@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        user = User.query.filter_by(email=email).first()
        if user:
            if not check_password_hash(user.password, password):
                flash("Incorrect password")
                return redirect(url_for('login'))
            elif not user:
                flash("User email doesn't exist.")
                return redirect(url_for('login'))
            else:
                login_user(user)
                return redirect(url_for('home'))
        else:
            flash("Please register.")
            return redirect(url_for('register'))
    return render_template('LOGIN.html', form=login_form, current_user=current_user)


# USER_PROFILE
@app.route('/profile', methods=["GET", "POST"])
@login_required
def profile():
    recent = UserHistory.query.all()
    return render_template("PROFILE.html", current_user=current_user, recent=recent)


# ABOUT_US
@app.route('/about', methods=["GET", "POST"])
def about():
    return render_template('about_us.html', current_user=current_user)


# LOGOUT_USER
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# CALCULATE
@app.route('/tryMy', methods=['POST', "GET"])
def get_json():
    val = request.get_json()

    # print(f'{val}')

    if User.query.filter_by(rfid=val['uid']).first():
        entry = Task.query.filter_by(uid_1=val['uid']).first()
        if not entry:
            val = request.get_json()
            pas = User.query.filter_by(rfid=val["uid"]).first()
            first_entry = Task(
                uid_1=val['uid'],
                dec_1=val['stp'],
                passenger=pas,
                initial_timestamp=(dt.now().strftime('%m/%d/%Y, %H:%M:%S')),
            )
            db.session.add(first_entry)
            db.session.commit()

        else:
            val_2 = request.get_json()
            # current_entry = Task.query.filter_by(uid_1=val_2['uid']).first()
            current_entry = Task.query.get(entry.id)

            if current_entry.due is None:
                if current_entry.dec_1 != val_2["stp"]:
                    current_entry.uid_2 = val_2['uid']
                    current_entry.dec_2 = val_2['stp']
                    current_entry.final_timestamp = (dt.now().strftime('%d/%m/%Y, %H:%M:%S'))
                    db.session.commit()

                    # print("Managed entries")

                    # Get stations from "Stations" DB.
                    station_1 = Stations.query.filter_by(station_hexa=entry.dec_1).first()
                    station_2 = Stations.query.filter_by(station_hexa=entry.dec_2).first()
                    # print('stations acquired')

                    # Calculate distance
                    distance_travelled = abs(
                        round(station_2.distance_from_initial - station_1.distance_from_initial, 2))
                    ticket_cost = abs(round(distance_travelled * 4, 0))
                    current_entry.due = ticket_cost
                    current_entry.distance = distance_travelled
                    db.session.commit()
                    # print(f"User travelled from {station_1.station_name} to {station_2.station_name}. Total travelled distance is {distance_travelled}KM. Total ticket cost is {ticket_cost}Rs.")

                    # db.session.delete(current_entry)
                    # db.session.commit()
                    # return f"Succeeded {station_1.station_name} to {station_2.station_name} {distance_travelled}KM {ticket_cost}Rs."
                    return ("100")
                else:
                    # return f"Try again both initial and end stations are same."
                    return ("101")
            else:
                # return f"Please clear your previous due of Rs.{current_entry.due}."
                return ("101")
        # return "Success"
        return ("100")
    else:
        # return "Rfid not present."
        return ("101")


@app.route('/process_pay', methods=["GET", "POST"])
@login_required
def process_pay():
    user_for_payment = request.args.get("user_id_for_payment")
    user_payment = Task.query.filter_by(passenger_id=user_for_payment).first()
    if user_payment:
        # print(user_payment.passenger.name)

        if user_payment.due is not None:
            user_due = float(user_payment.due)
            # print(type(user_due))

            client = razorpay.Client(auth=(razor_key, razor_secret))
            data = {"amount": (user_due * 100), "currency": "INR", "receipt": "order_rcptid_11"}
            payment = client.order.create(data=data)

            record_user_entry = UserHistory(
                card=user_payment.passenger.rfid,
                _from=Stations.query.filter_by(station_hexa=user_payment.dec_1).first().station_name,
                _to=Stations.query.filter_by(station_hexa=user_payment.dec_2).first().station_name,
                _from_time=user_payment.initial_timestamp,
                _to_time=user_payment.final_timestamp,
                travel_distance=user_payment.distance,
                ticket_due=user_payment.due,
                order_payment_id=payment["id"]
            )
            db.session.add(record_user_entry)
            db.session.commit()

            delete_processed_user_payment = Task.query.filter_by(id=user_payment.id).first()
            db.session.delete(delete_processed_user_payment)
            db.session.commit()

            # return render_template('successful_payment.html', payment=payment, _entry=record_user_entry),
            return render_template('successful_payment.html', payment=payment, _entry=record_user_entry)
        else:
            flash("No due payments.")
            return redirect(url_for('profile'))
    else:
        flash("User do not have any pending transaction.")
        return redirect(url_for('profile'))
        # return "Transaction needs not fulfilled."


# @app.route('/get_rfid', methods=["POST"])
# def get_rfid():
#     rf_id = request.form['uid']
#     session['my_var'] = rf_id
#     return "success"


# @app.route('/rfid/<int:user_id>', methods=["POST", "GET"])
# def rfid_get(user_id):
#     cnt_user_id = user_id
#     rf_id = session.get('my_var')
#     user_now = User.query.filter_by(id=cnt_user_id).first()
#     if user_now.rfid is None:
#         user_now.rfid = rf_id
#         db.session.commit()
#     return "RFID received"


# @app.route('/rfid/<int:user_id>', methods=["POST", "GET"])
# def rfid_get(user_id):
#     cnt_user_id = user_id
#     rf_id = session.get('my_var', None)
#     print(f'pass var: {rf_id}')
#     user_now = User.query.filter_by(id=cnt_user_id).first()
#     print(user_now.rfid)
#     if user_now.rfid is None:
#         user_now.rfid = rf_id
#         db.session.commit()
#         return render_template("admin_profile.html")
#     return "RFID received"


# @app.route('/extras')
# def extras():
#     return render_template('extras.html', table=df)


# @app.route('/s')
# def s():
#     payment = {"amount": 20, "id": "1asd", "status": "created", }
#     return render_template('successful_payment.html', payment=payment)


if __name__ == "__main__":
    app.run()
