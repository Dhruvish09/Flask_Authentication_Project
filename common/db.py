from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint

db = SQLAlchemy()

class BaseModel(db.Model):
    __abstract__ = True  # Indicates that this class should not be mapped to a database table
