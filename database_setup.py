from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Password(Base):
    __tablename__ = 'password'

    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

class ClothesType(Base):
    __tablename__ = 'clothesType'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
           'name': self.name,
           'id': self.id,
        }


class ClothingItem(Base):
    __tablename__ = 'clothing_item'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    type_id = Column(Integer, ForeignKey('clothesType.id'))
    clothesType = relationship(ClothesType)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
           'name': self.name,
           'description': self.description,
           'id': self.id,
           'type_id': self.type_id,
            }

engine = create_engine('sqlite:///wardrobe.db')

Base.metadata.create_all(engine)
