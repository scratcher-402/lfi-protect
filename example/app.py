import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Note, NoteShare, File
from datetime import datetime
import uuid
import json
import base64
import random

# Конфигурация
app = Flask(__name__)
app.config['SECRET_KEY'] = 'w31cOm3_t0_gB0ArD'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return '.' in filename and filename.rsplit(
    '.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_file(file, user_id, note_id):
    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit(
            '.', 1)[1].lower() if '.' in original_filename else ''
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        note_folder = os.path.join(user_folder, str(note_id))
        os.makedirs(note_folder, exist_ok=True)
        # Уязвимость - предсказуемое имя файла (можно легко предсказать)
        filename = f"{random.randint(1,9999)}.{file_extension}"
        file_path = os.path.join(note_folder, filename)
        new_file = File(
            filename=original_filename,
            unique_filename=filename,
            file_path=file_path,
            note_id=note_id,
            user_id=user_id
        )
        db.session.add(new_file)
        db.session.commit()
        file.save(file_path)
        return new_file
    return None


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Заполните все поля', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким логином уже существует', 'error')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация успешна! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный логин или пароль', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# flag{app_source_code_leaked}

@app.route('/dashboard')
@login_required
def dashboard():
    user_notes = Note.query.filter_by(user_id=current_user.id).all()

    shared_notes = Note.query.join(
        NoteShare, Note.id == NoteShare.note_id
    ).filter(
        NoteShare.shared_with_id == current_user.id
    ).all()

    return render_template('dashboard.html',
                         user_notes=user_notes,
                         shared_notes=shared_notes)


@app.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)

    if note.user_id != current_user.id:
        share = NoteShare.query.filter_by(
            note_id=note_id,
            shared_with_id=current_user.id
        ).first()

        if not share:
            abort(403)

    files = File.query.filter_by(note_id=note_id).all()
    shares = NoteShare.query.filter_by(
        note_id=note_id,
        note_owner_id=current_user.id
    ).all()
    shared_with = [share.shared_with_user for share in shares]

    return render_template('note.html',
                         note=note,
                         files=files,
                         shared_with=shared_with,
                         current_user=current_user,
                         can_edit=note.user_id == current_user.id)


@app.route('/note/<int:note_id>/share', methods=['GET', 'POST'])
@login_required
def share_note(note_id):
    note = Note.query.get_or_404(note_id)

    if note.user_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        username = request.form.get('username')

        if username == current_user.username:
            flash('Нельзя предоставить доступ самому себе', 'error')
            return redirect(url_for('share_note', note_id=note_id))

        user_to_share = User.query.filter_by(username=username).first()

        if not user_to_share:
            flash('Пользователь не найден', 'error')
            return redirect(url_for('share_note', note_id=note_id))

        existing_share = NoteShare.query.filter_by(
            note_id=note_id,
            shared_with_id=user_to_share.id
        ).first()
        if existing_share:
            flash('Доступ уже предоставлен этому пользователю', 'info')
        else:
            new_share = NoteShare(
                note_id=note_id,
                note_owner_id=current_user.id,
                shared_with_id=user_to_share.id
            )
            db.session.add(new_share)
            db.session.commit()
            flash(f'Доступ предоставлен пользователю {username}', 'success')

        return redirect(url_for('view_note', note_id=note_id))

    shares = NoteShare.query.filter_by(
        note_id=note_id,
        note_owner_id=current_user.id
    ).all()
    shared_with = [share.shared_with_user for share in shares]

    return render_template(
    'share_note.html',
    note=note,
     shared_with=shared_with)


@app.route('/note/<int:note_id>/unshare/<int:user_id>')
@login_required
def unshare_note(note_id, user_id):
    note = Note.query.get_or_404(note_id)

    if note.user_id != current_user.id:
        abort(403)

    share = NoteShare.query.filter_by(
        note_id=note_id,
        shared_with_id=user_id
    ).first()

    if share:
        db.session.delete(share)
        db.session.commit()
        flash('Доступ отозван', 'success')

    return redirect(url_for('share_note', note_id=note_id))


@app.route('/note/new', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        title = request.form.get('title', 'Без названия')
        content = request.form.get('content', '')
        note = Note(
            title=title,
            content=content,
            user_id=current_user.id
        )
        db.session.add(note)
        db.session.commit()

        files = request.files.getlist('files')
        for file in files:
            if file.filename:
                save_file(file, current_user.id, note.id)

        flash('Заметка создана!', 'success')
        return redirect(url_for('view_note', note_id=note.id))

    return render_template('edit_note.html', note=None)

    files = File.query.filter_by(note_id=note_id).all()
    shared_with = User.query.join(NoteShare).filter(
        NoteShare.note_id == note_id,
        NoteShare.note_owner_id == current_user.id
    ).all()

    return render_template('note.html',
                         note=note,
                         files=files,
                         shared_with=shared_with,
                         can_edit=note.user_id == current_user.id)


@app.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        note.title = request.form.get('title', 'Без названия')
        note.content = request.form.get('content', '')
        note.updated_at = datetime.utcnow()

        files = request.files.getlist('files')
        for file in files:
            if file.filename:
                save_file(file, current_user.id, note.id)

        db.session.commit()
        flash('Заметка обновлена!', 'success')
        return redirect(url_for('view_note', note_id=note.id))

    files = File.query.filter_by(note_id=note_id).all()
    return render_template('edit_note.html', note=note, files=files)


@app.route('/note/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    files = File.query.filter_by(note_id=note_id).all()
    for file in files:
        # Удаляем файл из файловой системы
        if os.path.exists(file.file_path):
            os.remove(file.file_path)
        db.session.delete(file)
    NoteShare.query.filter_by(note_id=note_id).delete()

    db.session.delete(note)
    db.session.commit()

    flash('Заметка удалена', 'success')
    return redirect(url_for('dashboard'))


@app.route('/file/<int:file_id>/delete')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.note.user_id != current_user.id:
        abort(403)
    if os.path.exists(file.file_path):
        os.remove(file.file_path)

    db.session.delete(file)
    db.session.commit()

    flash('Файл удален', 'success')
    return redirect(url_for('edit_note', note_id=file.note_id))


@app.route('/download')
@login_required
def download_file():
    if "application/json" == request.headers.get("Content-Type"):
        j = request.json
        if j.get("encoding") == "base64":
            # нетрадиционный формат запроса (base64) для демонстрации
            encoded_data = j.get("data")
            json_string = base64.b64decode(encoded_data).decode("utf-8")
            j = json.loads(json_string)
        user_id = j.get("user_id")
        note_id = j.get("note_id")
        filename = j.get("filename")
    else:
        user_id = request.args.get("user_id")
        note_id = request.args.get("note_id")
        filename = request.args.get("filename")

    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        share = NoteShare.query.filter_by(
            note_id=note.id,
            shared_with_id=current_user.id
        ).first()
        if not share:
            abort(403)
    
    # Небезопасное получение файла - ввод пользователя в имени никак не проверяется
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id), str(note_id), filename)
    print(file_path)
    return send_from_directory(".", file_path, as_attachment=True, download_name=filename)

# Инициализация
with app.app_context():
    db.create_all()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

if __name__ == '__main__':
    app.run(port=1544, debug=True)
