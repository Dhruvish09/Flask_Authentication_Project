from datetime import datetime
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from common.db import db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)

    user_roles = db.relationship("Role", secondary="user_role", backref="users", overlaps="user_roles,roles")
    
    def __repr__(self):
        return f"User('{self.first_name}', '{self.last_name}', '{self.email}', '{self.phone_number}')"

    def set_password(self, password):
        self.password = generate_password_hash(password).decode('utf-8')  # Set the password field

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def mark_email_verified(self):
        self.email_verified = True
        db.session.commit()

    def to_json(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone_number': self.phone_number
        }
    
    def has_role(self, role):
        return bool(Role.query.join(Role.user_roles)
                    .filter(User.id == self.id)
                    .filter(Role.slug == role)
                    .count() == 1)

class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(255))
    created_by = db.Column(db.String(100))
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    modified_by = db.Column(db.String(100))
    modified_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user_roles = db.relationship("User", secondary="user_role", backref="roles", overlaps="user_roles,users")
    
    def to_json(self):
        return {
            'role_name': self.role_name
        }
    

class UserRole(db.Model):
    __tablename__ = "user_role"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), primary_key=True)
