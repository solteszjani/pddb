# rendor_jelentes_app.py
import os, re
from datetime import datetime, date, timedelta
from calendar import monthrange
from flask_sqlalchemy import SQLAlchemy
import enum
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import mm
import sqlite3
from flask import Blueprint
from reportlab.platypus import Image as RLImage
from bs4 import BeautifulSoup
from flask import make_response
from weasyprint import HTML

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
PDF_FOLDER = os.path.join(BASE_DIR, 'PDF')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PDF_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'csere_egy_erosen_titkos_kulcsra_productionben'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'rendor_jelentes.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PDF_FOLDER'] = PDF_FOLDER
ALLOWED_EXT = {'pdf','png','jpg','jpeg','gif'}


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ----- Enums / Roles -----
class RoleEnum(enum.Enum):
    ADMIN = 'admin'
    SUPERVISOR = 'supervisor'
    OFFICER = 'officer'

# ----- Models -----
class Rank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    subdepartments = db.relationship('SubDepartment', back_populates='department', cascade='all,delete-orphan')

class SubDepartment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    department = db.relationship('Department', back_populates='subdepartments')

class Position(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)


    # További mezők pl. jelszó, rang, stb.

class WantedItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    crime = db.Column(db.String(500))
    creator_name = db.Column(db.String(100))
    type = db.Column(db.String(20))  # 'vehicle' vagy 'person'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Vehicle fields
    license_plate = db.Column(db.String(20))
    vehicle_type = db.Column(db.String(50))
    vehicle_color = db.Column(db.String(30))

    # Person fields
    person_name = db.Column(db.String(100))
    birth_place = db.Column(db.String(50))
    birth_date = db.Column(db.Date)
    mother_name = db.Column(db.String(100))
    address = db.Column(db.String(200))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    other_features = db.Column(db.String(200))

    # Common
    report_number = db.Column(db.String(50))
    reason = db.Column(db.String(200))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "crime": self.crime,
            "creator_name": self.creator_name,
            "type": self.type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "license_plate": self.license_plate or "",
            "vehicle_type": self.vehicle_type or "",
            "vehicle_color": self.vehicle_color or "",
            "person_name": self.person_name or "",
            "birth_place": self.birth_place or "",
            "birth_date": self.birth_date.isoformat() if self.birth_date else "",
            "mother_name": self.mother_name or "",
            "address": self.address or "",
            "email": self.email or "",
            "phone": self.phone or "",
            "other_features": self.other_features or "",
            "report_number": self.report_number or "",
            "reason": self.reason or ""
        }
class Wanted(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    crime = db.Column(db.Text)
    creator_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120))
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Enum(RoleEnum), default=RoleEnum.OFFICER, nullable=False)

    rank_id = db.Column(db.Integer, db.ForeignKey('rank.id'), nullable=True)
    rank = db.relationship('Rank')

    position_id = db.Column(db.Integer, db.ForeignKey('position.id'), nullable=True)
    position = db.relationship('Position')

    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    department = db.relationship('Department')

    subdepartment_id = db.Column(db.Integer, db.ForeignKey('sub_department.id'), nullable=True)
    subdepartment = db.relationship('SubDepartment')

    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ----- Jelszó kezelés -----
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ----- Jogosultságok -----
    def is_admin(self):
        return self.role == RoleEnum.ADMIN

    def is_supervisor(self):
        return self.role == RoleEnum.SUPERVISOR

    def can_edit_report(self, report):
        if not report:
            return False
        if self.is_admin() or self.is_supervisor():
            return True
        if self.position and self.position.name in ['Alosztályvezető', 'Osztályvezető']:
            return True
        return report.created_by_id == self.id or report.assignee_id == self.id

    def can_modify_department(self):
        high_ranks = ['Dandártábornok', 'Vezérőrnagy', 'Altábornagy']
        if self.rank and self.rank.name in high_ranks:
            return True
        if self.position and self.position.name in ['Alosztályvezető', 'Osztályvezető']:
            return True
        return False

    # ----- Sablon jogosultság -----
    def has_template_permission(self):
        if not self.position or not self.position.name:
            return False
        allowed = {
            "Alosztályvezető",
            "Osztályvezető",
            "Kapitányságvezető",
            "Kapitányságvezető-helyettes",
            "Altábornagy",
            "Vezérőrnagy",
            "Dandártábornok"
        }
        return self.position.name in allowed

    
class ShiftStatus(enum.Enum):
    TERVEZET = 'Tervezet'
    HITELES = 'Hiteles'

class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    shift_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(5))   # HH:MM
    end_time = db.Column(db.String(5))
    service_type = db.Column(db.String(50))
    car = db.Column(db.String(20))
    leader = db.Column(db.String(120))
    partner = db.Column(db.String(120))
    status = db.Column(db.String(20))  # "Tervezet" vagy "Hiteles"


class Action(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action_date = db.Column(db.Date, nullable=False)
    action_time = db.Column(db.Time, nullable=True)
    location = db.Column(db.String(300), nullable=False)

    person_name = db.Column(db.String(200))
    person_id_number = db.Column(db.String(120))
    vehicle_info = db.Column(db.String(300))

    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])

    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assignee = db.relationship('User', foreign_keys=[assignee_id])

    reports = db.relationship('Report', back_populates='action', cascade='all,delete-orphan')
    files = db.relationship('File', back_populates='action', cascade='all,delete-orphan')

class ReportStatus(enum.Enum):
    DRAFT = 'Nem hiteles'
    FILED = 'Hitelesítve'
    CLOSED = 'Lezárva'

class ReportType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # pl. "Bűnügyi"
    prefix = db.Column(db.String(10), nullable=False)               # pl. "01000"
    current_seq = db.Column(db.Integer, default=0)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])

    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assignee = db.relationship('User', foreign_keys=[assignee_id])

    report_type_id = db.Column(db.Integer, db.ForeignKey('report_type.id'), nullable=True)
    report_type = db.relationship('ReportType')

    filing_number = db.Column(db.String(80), unique=True, nullable=True)
    filing_date = db.Column(db.DateTime, nullable=True)

    status = db.Column(db.Enum(ReportStatus), default=ReportStatus.DRAFT)

    action_id = db.Column(db.Integer, db.ForeignKey('action.id'))
    action = db.relationship('Action', back_populates='reports')

    files = db.relationship('File', back_populates='report', cascade='all,delete-orphan')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    action_id = db.Column(db.Integer, db.ForeignKey('action.id'), nullable=True)
    action = db.relationship('Action', back_populates='files')

    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=True)
    report = db.relationship('Report', back_populates='files')

class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))
    content = db.Column(db.Text, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', backref='created_templates')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ----- Login manager -----
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----- Utils -----
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

def seed_metadata():
    # ranks
    if Rank.query.count() == 0:
        ranks = [
            'Őrmester', 'Törzsőrmester', 'Főtörzsőrmester', 'Zászlós', 'Törzszászlós',
            'Főtörzszászlós', 'Hadnagy', 'Főhadnagy', 'Százados', 'Őrnagy',
            'Alezredes', 'Ezredes', 'Dandártábornok', 'Vezérőrnagy', 'Altábornagy', 'Rendszergazda'
        ]
        for name in ranks:
            db.session.add(Rank(name=name))
        db.session.commit()

    # departments and subdepartments
    if Department.query.count() == 0:
        d1 = Department(name='Rendészeti Osztály')
        d2 = Department(name='Bűnügyi Osztály')
        d3 = Department(name='Szabálysértési Osztály')
        d4 = Department(name='IT')
        db.session.add_all([d1,d2,d3,d4])
        db.session.commit()
        sd_map = {
            'Rendészeti Osztály':['Járőrszolgálati Alosztály','Körzeti Megbízotti Alosztály'],
            'Bűnügyi Osztály':['Vizsgálati Alosztály','Nyomozói Alosztály'],
            'Szabálysértési Osztály':['Vizsgálati Osztály','Igazgatásrendészeti Alosztály'],
            'IT': ['IT']
        }
        for dept_name, subs in sd_map.items():
            dept = Department.query.filter_by(name=dept_name).first()
            for s in subs:
                db.session.add(SubDepartment(name=s, department=dept))
        db.session.commit()

    # positions
    if Position.query.count() == 0:
        positions = [
            'Járőr', 'Járőrvezető', 'Járőrparancsnok', 'Körzeti Megbízott', 'Szolgálatirányító parancsnok',
            'Előadó', 'Kiemelt előadó', 'Kiemelt Főelőadó', 'Alosztályvezető', 'Osztályvezető',
            'Kapitányságvezető-helyettes', 'Kapitányságvezető', 'Rendszergazda'
        ]
        for p in positions:
            db.session.add(Position(name=p))
        db.session.commit()

def ensure_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', full_name='Rendszergazda', role=RoleEnum.ADMIN)
        admin.set_password('admin')
        # set high rank if available
        admin.rank = Rank.query.filter_by(name='Rendszergazda').first() or Rank.query.first()
        admin.position = Position.query.filter_by(name='Rendszergazda').first() or None
        db.session.add(admin)
        db.session.commit()

def init_db():
    with app.app_context():
        db.create_all()
        seed_metadata()
        ensure_admin()

# Hívd meg közvetlenül az app indulásakor:
init_db()

# ----- Routes -----
@app.route('/')
def index():
    return redirect(url_for('reports'))

# --- AUTH ---
from flask import render_template_string
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            login_user(u)
            flash('Sikeres belépés.', 'success')
            return redirect(url_for('reports'))
        flash('Hibás felhasználónév vagy jelszó.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

def can_edit_shifts(user):
    return user.is_supervisor() or user.is_admin() or \
           (user.position and user.position.name in ['Alosztályvezető','Osztályvezető','Szolgálatirányító parancsnok'])


@app.route('/shifts')
@login_required
def shifts_redirect():
    today = date.today()
    return redirect(url_for('shifts', year=today.year, month=today.month))

# Eredeti route, paraméterekkel
@app.route('/shifts/<int:year>/<int:month>')
@login_required
def shifts(year, month):
    users = User.query.order_by(User.username).all()
    num_days = monthrange(year, month)[1]

    shifts_data = {u.id: {} for u in users}
    for user in users:
        for day in range(1, num_days+1):
            dt = date(year, month, day)
            shift = Shift.query.filter_by(user_id=user.id, shift_date=dt).first()
            if shift:
                shifts_data[user.id][dt] = shift

    prev_month, prev_year = (month-1, year) if month>1 else (12, year-1)
    next_month, next_year = (month+1, year) if month<12 else (1, year+1)

    return render_template('shifts.html',
                           users=users,
                           shifts_data=shifts_data,
                           num_days=num_days,
                           month=month,
                           year=year,
                           prev_month=prev_month,
                           prev_year=prev_year,
                           next_month=next_month,
                           next_year=next_year,
                           can_edit=can_edit_shifts(current_user),
                           date=date)

@app.route('/save_shift_ajax', methods=['POST'])
@login_required
def save_shift_ajax():
    if not can_edit_shifts(current_user):
        return jsonify({'success': False, 'msg': 'Nincs jogosultságod!'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'msg': 'Nincs adat!'}), 400

    try:
        dt = datetime.strptime(data['shift_date'], '%Y-%m-%d').date()
        shift = Shift.query.filter_by(user_id=data['user_id'], shift_date=dt).first()
        if not shift:
            shift = Shift(user_id=data['user_id'], shift_date=dt)
            db.session.add(shift)

        # Mivel SQLite nem támogat datetime.time típusú mezőt közvetlenül,
        # stringként tároljuk "HH:MM" formátumban
        shift.start_time = data.get('start_time')
        shift.end_time = data.get('end_time')
        shift.service_type = data.get('service_type')
        shift.car = data.get('car')
        shift.leader = data.get('leader')
        shift.partner = data.get('partner')
        shift.status = data.get('status')

        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/delete_shift_ajax', methods=['POST'])
@login_required
def delete_shift_ajax():
    if not can_edit_shifts(current_user):
        return jsonify({'success': False, 'msg': 'Nincs jogosultságod!'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'msg': 'Nincs adat!'}), 400

    try:
        dt = datetime.strptime(data['shift_date'], '%Y-%m-%d').date()
        shift = Shift.query.filter_by(user_id=data['user_id'], shift_date=dt).first()
        if shift:
            db.session.delete(shift)
            db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'msg': str(e)}), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Kijelentkeztél.', 'success')
    return redirect(url_for('login'))


# ----------------------------
# AJAX: Hozzáadás
# ----------------------------
@app.route('/wanted')
def wanted_list():
    items = WantedItem.query.all()
    items_dict = [item.to_dict() for item in items]
    return render_template('wanted.html', wanted_list=items_dict)


@app.route('/add_wanted', methods=['POST'])
def add_wanted():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Nincs adat'}), 400

    # birth_date konvertálása
    birth_date = data.get('birth_date')
    if birth_date:
        try:
            birth_date = datetime.strptime(birth_date, '%Y-%m-%d').date()
        except ValueError:
            birth_date = None
    else:
        birth_date = None

    item = WantedItem(
        type=data.get('type'),
        license_plate=data.get('license_plate'),
        vehicle_type=data.get('vehicle_type'),
        vehicle_color=data.get('vehicle_color'),
        person_name=data.get('person_name'),
        birth_place=data.get('birth_place'),
        birth_date=birth_date,  # ide már date objektum kerül
        mother_name=data.get('mother_name'),
        address=data.get('address'),
        email=data.get('email'),
        phone=data.get('phone'),
        other_features=data.get('other_features'),
        reason=data.get('reason')
    )

    db.session.add(item)
    db.session.commit()
    return jsonify({'success': True, 'id': item.id})

# Körözés törlése
@app.route('/delete_wanted/<int:item_id>', methods=['POST'])
def delete_wanted(item_id):
    item = WantedItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/update_wanted/<int:id>', methods=['PUT'])
@login_required
def update_wanted(id):
    item = WantedItem.query.get_or_404(id)
    data = request.get_json()
    item.name = data.get('name', item.name)
    item.crime = data.get('crime', item.crime)
    db.session.commit()
    return jsonify({'success': True})

# --- ACTIONS: create/list/view/edit/delete + search/filter ---
@app.route('/actions')
@login_required
def actions():
    q = Action.query.order_by(Action.action_date.desc())
    # filters
    kw = request.args.get('q','').strip()
    date_from = request.args.get('date_from','')
    date_to = request.args.get('date_to','')
    if kw:
        q = q.filter((Action.location.ilike(f'%{kw}%')) | (Action.person_name.ilike(f'%{kw}%')) | (Action.vehicle_info.ilike(f'%{kw}%')))
    if date_from:
        try:
            dfrom = datetime.strptime(date_from, '%Y-%m-%d').date()
            q = q.filter(Action.action_date >= dfrom)
        except:
            pass
    if date_to:
        try:
            dto = datetime.strptime(date_to, '%Y-%m-%d').date()
            q = q.filter(Action.action_date <= dto)
        except:
            pass
    items = q.all()
    return render_template('actions.html', actions=items, q=kw, date_from=date_from, date_to=date_to)

@app.route('/action/new', methods=['GET','POST'])
@login_required
def new_action():
    if request.method == 'POST':
        # datetime-local value like: '1999-05-05T12:22'
        dt_str = request.form.get('action_datetime')
        location = request.form.get('location','').strip()
        person_name = request.form.get('person_name','').strip()
        person_id = request.form.get('person_id','').strip()
        vehicle_info = request.form.get('vehicle_info','').strip()
        if not dt_str or not location:
            flash('Dátum/idő és helyszín kötelező.', 'danger')
            return redirect(url_for('new_action'))
        # parse ISO-like datetime-local
        try:
            dt = datetime.fromisoformat(dt_str)
        except Exception:
            flash('Hibás dátum/idő formátum.', 'danger')
            return redirect(url_for('new_action'))
        a = Action(action_date=dt.date(), action_time=dt.time(), location=location,
                   person_name=person_name, person_id_number=person_id, vehicle_info=vehicle_info,
                   created_by=current_user)
        db.session.add(a)
        db.session.commit()
        # files
        files = request.files.getlist('files')
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                # avoid overwrite
                base, ext = os.path.splitext(filename)
                i = 1
                while os.path.exists(dest):
                    filename = f"{base}_{i}{ext}"
                    dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    i += 1
                f.save(dest)
                file_rec = File(filename=filename, mimetype=f.mimetype, action=a)
                db.session.add(file_rec)
        db.session.commit()
        flash('Intézkedés létrehozva.', 'success')
        return redirect(url_for('view_action', action_id=a.id))
    return render_template('action_form.html', action=None)

@app.route('/action/<int:action_id>')
@login_required
def view_action(action_id):
    a = Action.query.get_or_404(action_id)
    # security: creator, assignee, supervisor, admin, certain positions
    can_view = (
        current_user.is_supervisor() or
        current_user.is_admin() or
        current_user == a.created_by or
        current_user == a.assignee or
        (current_user.position and current_user.position.name in ['Alosztályvezető','Osztályvezető'])
    )
    if not can_view:
        flash('Nincs jogosultságod megtekinteni az intézkedést.', 'danger')
        return redirect(url_for('actions'))

    # átadjuk a ReportStatus-t, hogy a sablonban a jelentések státusza megjelenjen
    return render_template('action_view.html', a=a, ReportStatus=ReportStatus)

@app.route('/action/<int:action_id>/edit', methods=['GET','POST'])
@login_required
def edit_action(action_id):
    a = Action.query.get_or_404(action_id)
    if not (current_user==a.created_by or current_user.is_supervisor() or current_user.is_admin() or (current_user.position and current_user.position.name in ['Alosztályvezető','Osztályvezető'])):
        flash('Nincs jogosultságod szerkeszteni.', 'danger')
        return redirect(url_for('view_action', action_id=action_id))
    if request.method == 'POST':
        dt_str = request.form.get('action_datetime')
        location = request.form.get('location','').strip()
        person_name = request.form.get('person_name','').strip()
        person_id = request.form.get('person_id','').strip()
        vehicle_info = request.form.get('vehicle_info','').strip()
        if dt_str:
            try:
                dt = datetime.fromisoformat(dt_str)
                a.action_date = dt.date()
                a.action_time = dt.time()
            except:
                flash('Hibás dátum/idő formátum.', 'danger')
                return redirect(url_for('edit_action', action_id=action_id))
        a.location = location
        a.person_name = person_name
        a.person_id_number = person_id
        a.vehicle_info = vehicle_info
        # files
        files = request.files.getlist('files')
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                base, ext = os.path.splitext(filename)
                i = 1
                while os.path.exists(dest):
                    filename = f"{base}_{i}{ext}"
                    dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    i += 1
                f.save(dest)
                file_rec = File(filename=filename, mimetype=f.mimetype, action=a)
                db.session.add(file_rec)
        db.session.commit()
        flash('Intézkedés frissítve.', 'success')
        return redirect(url_for('view_action', action_id=a.id))
    # prepare datetime-local value
    dt_local = datetime.combine(a.action_date, a.action_time) if a.action_time else datetime.combine(a.action_date, datetime.min.time())
    return render_template('action_form.html', action=a, dt_local=dt_local.isoformat(timespec='minutes'))

@app.route('/action/<int:action_id>/delete')
@login_required
def delete_action(action_id):
    a = Action.query.get_or_404(action_id)
    if not (current_user==a.created_by or current_user.is_supervisor() or current_user.is_admin() or (current_user.position and current_user.position.name in ['Alosztályvezető','Osztályvezető'])):
        flash('Nincs jogosultságod törölni.', 'danger')
        return redirect(url_for('view_action', action_id=action_id))
    db.session.delete(a)
    db.session.commit()
    flash('Intézkedés törölve.', 'success')
    return redirect(url_for('actions'))


# --- REPORTS: list/filter/create/edit/delete/view/file/upload/assign/file_report/export ---
@app.route('/reports')
@login_required
def reports():
    q = Report.query.order_by(Report.updated_at.desc())
    kw = request.args.get('q','').strip()
    status = request.args.get('status','')
    assignee = request.args.get('assignee','')
    date_from = request.args.get('date_from','')
    date_to = request.args.get('date_to','')
    if kw:
        q = q.filter((Report.title.ilike(f'%{kw}%')) | (Report.content.ilike(f'%{kw}%')))
    if status:
        try:
            q = q.filter(Report.status == ReportStatus(status))
        except:
            pass
    if assignee:
        try:
            a_id = int(assignee)
            q = q.filter(Report.assignee_id == a_id)
        except:
            pass
    if date_from:
        try:
            df = datetime.strptime(date_from, '%Y-%m-%d')
            q = q.filter(Report.created_at >= df)
        except:
            pass
    if date_to:
        try:
            dt = datetime.strptime(date_to, '%Y-%m-%d')
            q = q.filter(Report.created_at <= dt)
        except:
            pass
    items = q.all()
    users = User.query.order_by(User.username).all()
    return render_template('reports.html', reports=items, q=kw, status=status, users=users, assignee=assignee, date_from=date_from, date_to=date_to)

@app.route('/report/new', methods=['GET','POST'])
@login_required
def new_report():
    # Előre definiált jelentéstípusok és prefixek
    report_types_def = {
        "Rendőri jelentés": "id",
        "Feljegyzés": "ált",
        "Szabálysértési feljelentés": "SZABS",
        "Jelentés elfogás/előállításról": "id",
        "Jelentés letartóztatásról": "bü",
        "Határozat": "ált",
        "Szolgálati jegy": "ált",
        "Parancsnoki kivizsgálás": "id",
        "Jelentés tanú/gyanúsított kihallgatásáról": "bü",
        "Határozat tárgy lefoglalásról": "id"
    }

    actions = Action.query.order_by(Action.action_date.desc()).all()
    users = User.query.order_by(User.username).all()

    if request.method == 'POST':
        action_id = request.form.get('action_id')
        title = request.form.get('title','').strip()
        content = request.form.get('content','').strip()
        assignee_id = request.form.get('assignee_id') or None
        report_type_name = request.form.get('report_type_id')

        # Validáció
        if not action_id:
            flash('Először válassz vagy hozz létre intézkedést.', 'danger')
            return redirect(url_for('new_report'))
        if not title:
            flash('Cím szükséges.', 'danger')
            return redirect(url_for('new_report'))
        if report_type_name not in report_types_def:
            flash('Érvénytelen jelentéstípus.', 'danger')
            return redirect(url_for('new_report'))

        action = Action.query.get(int(action_id))

        # ReportType lekérése vagy létrehozása
        report_type = ReportType.query.filter_by(name=report_type_name).first()
        if not report_type:
            report_type = ReportType(
                name=report_type_name,
                prefix=report_types_def[report_type_name],
                current_seq=0
            )
            db.session.add(report_type)
            db.session.commit()

        # Létrehozás
        r = Report(title=title, content=content, created_by=current_user, action=action, report_type=report_type)
        if assignee_id:
            r.assignee = User.query.get(int(assignee_id))
            if action:
                action.assignee = r.assignee

        # Ügyszám generálás
        report_type.current_seq += 1
        db.session.commit()  # először mentjük a current_seq-et
        r.filing_number = f"01000/{report_type.current_seq}/{datetime.utcnow().year}.{report_type.prefix}"
        r.filing_date = datetime.utcnow()
        r.status = ReportStatus.FILED  # azonnal iktatva
        db.session.add(r)

        # Fájlok kezelése
        files = request.files.getlist('files')
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                base, ext = os.path.splitext(filename)
                i = 1
                while os.path.exists(dest):
                    filename = f"{base}_{i}{ext}"
                    dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    i += 1
                f.save(dest)
                file_rec = File(filename=filename, mimetype=f.mimetype, report=r)
                db.session.add(file_rec)

        db.session.commit()
        flash(f'Jelentés létrehozva és iktatva: {r.filing_number}', 'success')
        return redirect(url_for('view_report', report_id=r.id))

    return render_template(
        'report_form.html',
        report=None,
        actions=actions,
        users=users,
        report_types=list(report_types_def.keys())
    )



@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    r = Report.query.get_or_404(report_id)
    # security: csak jogosultak láthatják
    can_view = (
        current_user.is_supervisor() or
        current_user.is_admin() or
        current_user == r.created_by or
        current_user == r.assignee or
        (r.action and (current_user == r.action.created_by or current_user == r.action.assignee)) or
        (current_user.position and current_user.position.name in ['Alosztályvezető', 'Osztályvezető'])
    )
    if not can_view:
        flash('Nincs jogosultságod megtekinteni a jelentést.', 'danger')
        return redirect(url_for('reports'))

    # átadjuk a ReportStatus-t a sablonnak
    return render_template('report_view.html', r=r, ReportStatus=ReportStatus)

@app.route('/report/<int:report_id>/edit', methods=['GET','POST'])
@login_required
def edit_report(report_id):
    r = Report.query.get_or_404(report_id)
    if not current_user.can_edit_report(r):
        flash('Nincs jogosultságod szerkeszteni a jelentést.', 'danger')
        return redirect(url_for('view_report', report_id=report_id))

    actions = Action.query.order_by(Action.action_date.desc()).all()
    report_types = ReportType.query.order_by(ReportType.name).all()
    users = User.query.order_by(User.username).all()

    if request.method == 'POST':
        r.title = request.form.get('title','').strip()
        r.content = request.form.get('content','').strip()
        assignee_id = request.form.get('assignee_id') or None
        report_type_name = request.form.get('report_type_id') or None  # a név jön a formból

        if assignee_id:
            r.assignee = User.query.get(int(assignee_id))
            if r.action:
                r.action.assignee = r.assignee

        if report_type_name:
            # lekérjük a ReportType-ot név alapján
            report_type = ReportType.query.filter_by(name=report_type_name).first()
            if report_type:
                r.report_type = report_type

        # fájlok feltöltése
        files = request.files.getlist('files')
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                base, ext = os.path.splitext(filename)
                i = 1
                while os.path.exists(dest):
                    filename = f"{base}_{i}{ext}"
                    dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    i += 1
                f.save(dest)
                file_rec = File(filename=filename, mimetype=f.mimetype, report=r)
                db.session.add(file_rec)

        db.session.commit()
        flash('Jelentés mentve.', 'success')
        return redirect(url_for('view_report', report_id=r.id))

    return render_template(
        'report_form.html', 
        report=r, 
        users=users, 
        actions=actions, 
        report_types=[rt.name for rt in report_types]
    )



@app.route('/report/<int:report_id>/delete')
@login_required
def delete_report(report_id):
    r = Report.query.get_or_404(report_id)
    if not current_user.can_edit_report(r):
        flash('Nincs jogosultságod törölni a jelentést.', 'danger')
        return redirect(url_for('view_report', report_id=report_id))
    db.session.delete(r)
    db.session.commit()
    flash('Jelentés törölve.', 'success')
    return redirect(url_for('reports'))

@app.route('/report/<int:report_id>/assign', methods=['GET','POST'])
@login_required
def assign_report(report_id):
    r = Report.query.get_or_404(report_id)
    if not (current_user.is_supervisor() or current_user.is_admin() or (current_user.position and current_user.position.name in ['Alosztályvezető','Osztályvezető'])):
        flash('Nincs jogosultságod kiosztani.', 'danger')
        return redirect(url_for('view_report', report_id=report_id))
    if request.method == 'POST':
        assignee_id = request.form.get('assignee_id')
        if assignee_id:
            r.assignee = User.query.get(int(assignee_id))
            if r.action:
                r.action.assignee = r.assignee
            db.session.commit()
            flash('Kiosztva: ' + r.assignee.username, 'success')
            return redirect(url_for('view_report', report_id=report_id))
    users = User.query.order_by(User.username).all()
    return render_template('assign_form.html', r=r, users=users)


@app.route('/report/<int:report_id>/file')
@login_required
def file_report(report_id):
    r = Report.query.get_or_404(report_id)
    
    # Jogosultság: csak a létrehozó
    if r.created_by != current_user:
        flash('Csak a jelentés létrehozója iktathatja.', 'danger')
        return redirect(url_for('view_report', report_id=report_id))
    
    if r.status == ReportStatus.FILED:
        flash('A jelentés már iktatott.', 'danger')
        return redirect(url_for('view_report', report_id=report_id))
    
    # Előre definiált típus rövidítések
    REPORT_TYPE_SHORT = {
        "Rendőri jelentés": "id",
        "Feljegyzés": "ált",
        "Szabálysértési feljelentés": "SZABS",
        "Jelentés elfogás/előállításról": "id",
        "Jelentés letartóztatásról": "bü",
        "Határozat": "ált",
        "Szolgálati jegy": "ált",
        "Parancsnoki kivizsgálás": "id",
        "Jelentés tanú/gyanúsított kihallgatásáról": "bü",
        "Határozat tárgy lefoglalásról": "id"
    }

    if r.report_type.current_seq is None:
        r.report_type.current_seq = 0
    r.report_type.current_seq += 1

    year = datetime.utcnow().year
    short = REPORT_TYPE_SHORT.get(r.report_type.name, r.report_type.name[:2].lower())

    filing_number = f"{r.report_type.prefix}/{r.report_type.current_seq}/{year}.{short}"

    r.filing_number = filing_number
    r.filing_date = datetime.utcnow()
    r.status = ReportStatus.FILED

    db.session.commit()
    flash('Iktatva: ' + filing_number, 'success')
    return redirect(url_for('view_report', report_id=report_id))


@app.route('/export_report_pdf/<int:report_id>')
@login_required
def export_report_pdf(report_id):
    report = Report.query.get_or_404(report_id)

    # FONT regisztrálás (DejaVu ékezetekhez)
    font_path = os.path.join(BASE_DIR, 'static', 'fonts', 'DejaVuSans.ttf')
    if not os.path.exists(font_path):
        return f"Hiba: DejaVu betűtípus nem található: {font_path}"
    pdfmetrics.registerFont(TTFont('DejaVu', font_path))

    # PDF mappa
    pdf_folder = app.config.get('PDF_FOLDER') or os.path.join(BASE_DIR, 'static', 'export')
    os.makedirs(pdf_folder, exist_ok=True)
    filename = f"jelentes_{report.id}.pdf"
    pdf_path = os.path.join(pdf_folder, filename)

    # Dokumentum
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=25*mm,
        leftMargin=25*mm,
        topMargin=30*mm,
        bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='DejaVuJustify',
        fontName='DejaVu',
        fontSize=11,
        leading=14,
        alignment=TA_JUSTIFY
    ))
    styles.add(ParagraphStyle(
        name='Meta',
        fontName='DejaVu',
        fontSize=10,
        leading=12
    ))

    story = []

    # HEADER / FOOTER
    logo_path = os.path.join(BASE_DIR, 'static', 'img', 'lspd_logo.png')
    def header_footer(canvas, doc):
        canvas.saveState()
        w, h = A4
        if os.path.exists(logo_path):
            img_w = 40*mm
            img = RLImage(logo_path)
            orig_w, orig_h = img.imageWidth, img.imageHeight
            img_h = img_w * (orig_h / orig_w)
            x = (w - img_w)/2
            y = h - 30*mm
            canvas.drawImage(logo_path, x, y, width=img_w, height=img_h, preserveAspectRatio=True, mask='auto')
        canvas.setFont('DejaVu', 14)
        canvas.drawCentredString(w/2.0, h - 45*mm, "Los Santos Police Department")
        canvas.setFont('DejaVu', 11)
        canvas.drawCentredString(w/2.0, h - 52*mm, "Rendőrségi Jelentés")
        canvas.setLineWidth(0.5)
        canvas.line(25*mm, h - 55*mm, w - 25*mm, h - 55*mm)
        footer_text = f"Generálva: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        canvas.setFont('DejaVu', 9)
        canvas.drawRightString(w - 25*mm, 15*mm, footer_text)
        canvas.restoreState()

    # META adatok
    date_val = getattr(report, 'filing_date', None) or getattr(report, 'created_at', None)
    if date_val:
        story.append(Paragraph(f"<b>Dátum:</b> {date_val.strftime('%Y-%m-%d %H:%M')}", styles['Meta']))
        story.append(Spacer(1,6))
    creator = getattr(report.created_by, 'full_name', None) or getattr(report.created_by, 'username', None)
    if creator:
        story.append(Paragraph(f"<b>Létrehozó:</b> {creator}", styles['Meta']))
        story.append(Spacer(1,6))
    if getattr(report, 'report_type', None):
        story.append(Paragraph(f"<b>Típus:</b> {report.report_type.name}", styles['Meta']))
        story.append(Spacer(1,6))
    if getattr(report, 'filing_number', None):
        story.append(Paragraph(f"<b>Ügyszám:</b> {report.filing_number}", styles['Meta']))
        story.append(Spacer(1,6))
    location = getattr(report.action, 'location', None)
    if location:
        story.append(Paragraph(f"<b>Helyszín:</b> {location}", styles['Meta']))
        story.append(Spacer(1,8))

    # TARTALOM - Quill HTML feldolgozása
    content_html = getattr(report, 'content', '') or ''
    soup = BeautifulSoup(content_html, 'html.parser')

    def parse_node(node):
        # bekezdések
        if node.name == 'p' or node.name is None:
            text = str(node)
            style = styles['DejaVuJustify']
            # font-size ellenőrzés
            if node.name == 'span' and node.get('style'):
                m = re.search(r'font-size:(\d+)px', node['style'])
                if m:
                    size = int(m.group(1))
                    style = ParagraphStyle('temp', parent=styles['DejaVuJustify'], fontSize=size)
            story.append(Paragraph(node.decode_contents() if hasattr(node,'decode_contents') else str(node), style))
            story.append(Spacer(1,6))
        # listák
        elif node.name in ['ul','ol']:
            items = []
            for li in node.find_all('li', recursive=False):
                items.append(ListItem(Paragraph(li.decode_contents(), styles['DejaVuJustify'])))
            bullet_type = 'bullet' if node.name=='ul' else '1'
            story.append(ListFlowable(items, bulletType=bullet_type))
            story.append(Spacer(1,6))
        # rekurzív feldolgozás
        else:
            for child in node.children:
                parse_node(child)

    for child in soup.children:
        parse_node(child)

    # PDF generálás
    try:
        doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    except Exception as e:
        return f"Hiba a PDF generálásnál: {e}"

    return send_from_directory(pdf_folder, filename, as_attachment=True)


# --- FILE DOWNLOAD ---
@app.route('/uploads/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], path=filename, as_attachment=True)


# --- ADMIN: manage users, ranks, departments, subdepartments, positions ---
@app.route('/admin')
@login_required
def admin_index():
    if not current_user.is_admin():
        flash('Csak admin férhet hozzá.', 'danger')
        return redirect(url_for('index'))
    users = User.query.order_by(User.username).all()
    ranks = Rank.query.order_by(Rank.id).all()
    departments = Department.query.order_by(Department.name).all()
    positions = Position.query.order_by(Position.name).all()
    return render_template('admin_index.html', users=users, ranks=ranks, departments=departments, positions=positions)


@app.route('/admin/user/new', methods=['GET','POST'])
@login_required
def admin_user_new():
    if not current_user.is_admin():
        flash('Csak admin férhet hozzá.', 'danger')
        return redirect(url_for('admin_index'))
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        full_name = request.form.get('full_name','').strip()
        password = request.form.get('password','').strip()
        role = request.form.get('role','officer')
        rank_id = request.form.get('rank_id') or None
        position_id = request.form.get('position_id') or None
        department_id = request.form.get('department_id') or None
        subdepartment_id = request.form.get('subdepartment_id') or None
        if not username or not password:
            flash('Felhasználónév és jelszó szükséges.', 'danger')
            return redirect(url_for('admin_user_new'))
        if User.query.filter_by(username=username).first():
            flash('A felhasználónév már létezik.', 'danger')
            return redirect(url_for('admin_user_new'))
        u = User(username=username, full_name=full_name, role=RoleEnum(role))
        u.set_password(password)
        if rank_id:
            u.rank = Rank.query.get(int(rank_id))
        if position_id:
            u.position = Position.query.get(int(position_id))
        if department_id:
            u.department = Department.query.get(int(department_id))
        if subdepartment_id:
            u.subdepartment = SubDepartment.query.get(int(subdepartment_id))
        db.session.add(u)
        db.session.commit()
        flash('Felhasználó létrehozva.', 'success')
        return redirect(url_for('admin_index'))
    ranks = Rank.query.order_by(Rank.id).all()
    departments = Department.query.order_by(Department.name).all()
    positions = Position.query.order_by(Position.name).all()
    subdeps = SubDepartment.query.order_by(SubDepartment.name).all()
    return render_template('admin_user_form.html', ranks=ranks, departments=departments, positions=positions, subdeps=subdeps)

@app.route('/admin/user/<int:user_id>/delete')
@login_required
def admin_user_delete(user_id):
    if not current_user.is_admin():
        flash('Csak admin férhet hozzá.', 'danger')
        return redirect(url_for('admin_index'))
    u = User.query.get_or_404(user_id)
    if u.username == 'admin':
        flash('Alap admin törölése nem engedélyezett.', 'danger')
        return redirect(url_for('admin_index'))
    db.session.delete(u)
    db.session.commit()
    flash('Felhasználó törölve.', 'success')
    return redirect(url_for('admin_index'))

@app.route('/admin/meta', methods=['GET','POST'])
@login_required
def admin_meta():
    if not (current_user.is_admin() or current_user.can_modify_department()):
        flash('Nincs jogosultságod módosítani a metaadatokat.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # --- meglévő mezők ---
        if 'rank_name' in request.form:
            name = request.form.get('rank_name').strip()
            if name:
                db.session.add(Rank(name=name))
        if 'department_name' in request.form:
            name = request.form.get('department_name').strip()
            if name:
                db.session.add(Department(name=name))
        if 'subdepartment_name' in request.form:
            name = request.form.get('subdepartment_name').strip()
            dept_id = request.form.get('meta_department_id')
            if name and dept_id:
                db.session.add(SubDepartment(name=name, department=Department.query.get(int(dept_id))))
        if 'position_name' in request.form:
            name = request.form.get('position_name').strip()
            if name:
                db.session.add(Position(name=name))
        
        # --- új jelentéstípus ---
        if 'report_type_name' in request.form and 'report_type_prefix' in request.form:
            name = request.form.get('report_type_name').strip()
            prefix = request.form.get('report_type_prefix').strip()
            if name and prefix:
                db.session.add(ReportType(name=name, prefix=prefix))
        
        db.session.commit()
        flash('Metaadatok frissítve.', 'success')
        return redirect(url_for('admin_meta'))

    # GET rész
    ranks = Rank.query.order_by(Rank.id).all()
    departments = Department.query.order_by(Department.name).all()
    subdeps = SubDepartment.query.order_by(SubDepartment.name).all()
    positions = Position.query.order_by(Position.name).all()
    report_types = ReportType.query.order_by(ReportType.name).all()
    
    return render_template(
        'admin_meta.html', 
        ranks=ranks, 
        departments=departments, 
        subdeps=subdeps, 
        positions=positions,
        report_types=report_types
    )

@app.route('/admin/meta/delete/<string:kind>/<int:obj_id>')
@login_required
def admin_meta_delete(kind, obj_id):
    if not (current_user.is_admin() or current_user.can_modify_department()):
        flash('Nincs jogosultságod módosítani a metaadatokat.', 'danger')
        return redirect(url_for('admin_meta'))
    
    if kind == 'rank':
        o = Rank.query.get_or_404(obj_id)
    elif kind == 'department':
        o = Department.query.get_or_404(obj_id)
    elif kind == 'subdepartment':
        o = SubDepartment.query.get_or_404(obj_id)
    elif kind == 'position':
        o = Position.query.get_or_404(obj_id)
    elif kind == 'report_type':    # új
        o = ReportType.query.get_or_404(obj_id)
    else:
        flash('Ismeretlen típus.', 'danger')
        return redirect(url_for('admin_meta'))
    
    db.session.delete(o)
    db.session.commit()
    flash('Törölve.', 'success')
    return redirect(url_for('admin_meta'))


@app.route('/user/<int:user_id>/edit_modal', methods=['POST'])
@login_required
def edit_user_modal(user_id):
    user = User.query.get_or_404(user_id)

    editable_positions = ["Alosztályvezető", "Osztályvezető",
                          "Kapitányságvezető-helyettes", "Kapitányságvezető"]
    editable_ranks = ["Dandártábornok", "Vezérőrnagy", "Altábornagy"]

    can_edit = (current_user.position and current_user.position.name in editable_positions) \
               or (current_user.rank and current_user.rank.name in editable_ranks) \
               or current_user.is_admin()

    if not can_edit:
        flash('Nincs jogosultságod módosítani ezt a felhasználót.', 'danger')
        return redirect(url_for('list_users'))

    user.username = request.form.get('username')
    user.full_name = request.form.get('full_name')
    rank_id = request.form.get('rank_id')
    position_id = request.form.get('position_id')
    department_id = request.form.get('department_id')
    subdepartment_id = request.form.get('subdepartment_id')

    if rank_id:
        user.rank_id = int(rank_id)
    if position_id:
        user.position_id = int(position_id)
    if department_id:
        user.department_id = int(department_id)
    if subdepartment_id:
        user.subdepartment_id = int(subdepartment_id)

    db.session.commit()
    flash('Felhasználó adatai frissítve.', 'success')
    return redirect(url_for('list_users'))


@app.route('/user/<int:user_id>/edit', methods=['POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if not can_current_user_edit(user):
        flash('Nincs jogosultságod módosítani ezt a felhasználót.', 'danger')
        return redirect(url_for('list_users'))

    user.full_name = request.form.get('full_name')
    rank_id = request.form.get('rank_id')
    position_id = request.form.get('position_id')
    department_id = request.form.get('department_id')
    subdepartment_id = request.form.get('subdepartment_id')

    if rank_id:
        user.rank_id = int(rank_id)
    if position_id:
        user.position_id = int(position_id)
    if department_id:
        user.department_id = int(department_id)
    if subdepartment_id:
        user.subdepartment_id = int(subdepartment_id)

    db.session.commit()
    flash('Felhasználó adatai frissítve.', 'success')
    return redirect(url_for('list_users'))


def can_current_user_edit(target_user):
    editable_positions = ["Alosztályvezető", "Osztályvezető",
                          "Kapitányságvezető-helyettes", "Kapitányságvezető"]
    editable_ranks = ["Dandártábornok", "Vezérőrnagy", "Altábornagy"]
    return (current_user.position and current_user.position.name in editable_positions) or \
           (current_user.rank and current_user.rank.name in editable_ranks) or \
           current_user.is_admin()

@app.route('/users')
@login_required
def list_users():
    users = User.query.order_by(User.username).all()
    ranks = Rank.query.order_by(Rank.id).all()
    departments = Department.query.order_by(Department.name).all()
    positions = Position.query.order_by(Position.name).all()
    subdeps = SubDepartment.query.order_by(SubDepartment.name).all()
    return render_template(
        'users.html',
        users=users,
        ranks=ranks,
        departments=departments,
        positions=positions,
        subdeps=subdeps
    )


# ----- Run -----
if __name__ == '__main__':
    app.run(debug=True)
    port = int(os.environ.get("PORT", 5000))  # Render a PORT változóban adja
    app.run(host="0.0.0.0", port=port, debug=False)

from flask_sqlalchemy import SQLAlchemy

from reportlab.lib.utils import ImageReader as RLImage


