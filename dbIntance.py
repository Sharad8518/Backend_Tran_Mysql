from flask import Flask
from flask_restful import Api, Resource, reqparse,request
from flask_sqlalchemy import SQLAlchemy
import os
app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQLALCHEMY_DATABASE_URI")
db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
     db.drop_all()
     db.create_all()
