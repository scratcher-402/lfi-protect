from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.relationship('Note', backref='owner', lazy=True, foreign_keys='Note.user_id')
    
    # Заметки, к которым предоставили доступ этому пользователю
    notes_shared_with_me = db.relationship(
        'NoteShare',
        foreign_keys='NoteShare.shared_with_id',
        backref='shared_with_user',
        lazy=True
    )
    
    # Заметки, которые этот пользователь предоставил другим
    notes_i_shared = db.relationship(
        'NoteShare',
        foreign_keys='NoteShare.note_owner_id',
        backref='sharing_user',
        lazy=True
    )

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, default='Без названия')
    content = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    files = db.relationship('File', backref='note', lazy=True, cascade='all, delete-orphan')
    
    # Пользователи, которым предоставлен доступ
    shares = db.relationship(
        'NoteShare',
        foreign_keys='NoteShare.note_id',
        backref='shared_note',
        lazy=True,
        cascade='all, delete-orphan'
    )

class NoteShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    note_owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('note_id', 'shared_with_id', name='unique_note_share'),)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(500), nullable=False)
    unique_filename = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='files')
