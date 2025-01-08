
from datetime import datetime
import os
from os.path import join, dirname
import time
from functools import wraps
from sqlalchemy.types import DATE
from sqlalchemy import Column, Integer, Text, Float, TIMESTAMP,DateTime, ForeignKey, create_engine, BigInteger, String, func,Date,Boolean
from sqlalchemy.exc import OperationalError, StatementError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import and_, or_, not_
from os import environ
from dotenv import load_dotenv

# from dbIntance import *

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

DB_URL = os.environ.get("FLEE_DATABASE_URL")
print('==================================================')
# print(DB_URL)
base = declarative_base()
engine = create_engine(DB_URL, pool_recycle=3306, connect_args={'connect_timeout': 60})
# print(engine)
print('**************************************************')

session = sessionmaker(bind=engine)

class Users(base):
	__tablename__ = 'users'
	userId = Column(Integer, primary_key=True)
	email = Column(Text)
	password = Column(Text)
	passwordResetToken = Column(Text)
	passwordResetExpires = Column(Text)
	role = Column(Text)
	isVerified = Column(Integer)
	firebaseUid = Column(Text)
	signupTimestamp = Column(TIMESTAMP)
	status=Column(Boolean,unique=False,default=True)
	fcmtoken=Column(Text)

class UserTokens(base):
	__tablename__ = 'user_tokens'
	_id = Column(Integer, primary_key=True)
	_userId = Column(Integer, ForeignKey('users.userId'))
	userToken = Column(Text)
	timestamp = Column(TIMESTAMP)

class ConsignorMasterData(base):
	__tablename__ = 'consignor_masterdata'
	_id = Column(Integer, primary_key=True)
	userId = Column(Integer, ForeignKey('users.userId'))
	userName = Column(Text)
	companyName = Column(Text)
	adminName = Column(Text)
	email = Column(Text)
	contact = Column(Text)
	gstNumber = Column(Text)
	panNumber = Column(Text)
	timestamp = Column(TIMESTAMP)
	

class SupervisorMasterData(base):
	__tablename__ = 'supervisor'
	_id = Column(Integer, primary_key=True)
	userName=Column(Text)
	userId = Column(Integer, ForeignKey('users.userId'))
	consignorId = Column(Integer, ForeignKey('consignor_masterdata._id'))
	contact = Column(Text)
	timestamp = Column(TIMESTAMP)

class ConsignorAddress(base):
	__tablename__ = 'consignor_address'
	_id = Column(Integer, primary_key=True)
	address = Column(Text)
	location = Column(Text)
	state = Column(Text)
	district = Column(Text)
	pincode = Column(Text)
	consignorId = Column(Integer, ForeignKey('users.userId'))
	isDefault = Column(Boolean, unique=False, default=False)
	timestamp = Column(TIMESTAMP)

class TransporterMasterData(base):
	__tablename__ = 'transporter_masterdata'
	_id = Column(Integer, primary_key=True)
	userId = Column(Integer, ForeignKey('users.userId'))
	userName = Column(Text)
	companyName = Column(Text)
	adminName = Column(Text)
	managerName = Column(Text)
	email = Column(Text)
	contact = Column(Text)
	address = Column(Text)
	pincode = Column(Text)
	location = Column(Text)
	gstNumber = Column(Text)
	panNumber = Column(Text)
	truckCount = Column(Integer)
	timestamp = Column(TIMESTAMP)
	

class ConsigneeMasterData(base):
	__tablename__ = 'consignee_masterdata'
	_id = Column(Integer, primary_key=True)
	userId = Column(Integer, ForeignKey('users.userId'))
	consignorId = Column(Integer, ForeignKey('users.userId'))
	userName = Column(Text)
	email = Column(Text)
	contact = Column(Text)
	address = Column(Text)
	pincode = Column(Text)
	location = Column(Text)
	district = Column(Text)
	state = Column(Text)
	gstNumber = Column(Text)
	panNumber = Column(Text)
	companyName = Column(Text)
	adminName = Column(Text)
	managerName = Column(Text)
	addByConsignor = Column(Integer)
	timestamp = Column(TIMESTAMP)



class Enquiry(base):
	__tablename__ = 'enquiries'
	_id = Column(Integer, primary_key=True)
	enquiryBy = Column(Integer,ForeignKey('users.userId'))
	toConsigneeId = Column(Integer,ForeignKey('users.userId'))
	pickupAddresssId = Column(Integer,ForeignKey('consignor_address._id'))
	weight = Column(Text)
	truckType = Column(Text)
	material = Column(Text)
	unloadingExpense = Column(Integer)
	loadingExpense = Column(Integer)
	loadingTime = Column(DateTime)
	advance = Column(Integer)
	againstBill = Column(Integer)
	remarks = Column(Text)
	timestamp = Column(TIMESTAMP)
	enquirystatus=Column(Integer,default=0)

class SelectedTransporter(base):
	__tablename__ = 'selected_transporters'
	_id = Column(Integer, primary_key=True)
	enquiryId = Column(Integer,ForeignKey('enquiries._id'))
	selectedTransporterId = Column(Integer, ForeignKey('transporter_masterdata._id'))

class TruckType(base):
	__tablename__ = 'truck_type'
	_id = Column(Integer,primary_key=True)
	truckType = Column(Text)
	mt = Column(Text)

class TransporterRoutes(base):
	__tablename__ = 'transporter_routes'
	_id = Column(Integer, primary_key=True)
	userId = Column(Integer, ForeignKey('users.userId'))
	toAddress = Column(Text)
	fromAddress = Column(Text)

class Bids(base):
	__tablename__ = 'bids'
	_id = Column(Integer, primary_key=True)
	transporterId = Column(Integer, ForeignKey('users.userId'))
	enquiryId = Column(Integer, ForeignKey('enquiries._id'))
	advance = Column(Integer)
	againstBill = Column(Integer)
	pickup = Column(DateTime)
	estimatedDelivery = Column(DateTime)
	remarks = Column(Text)
	status = Column(Text)
	timestamp = Column(TIMESTAMP)
	bid_rate_type = Column(Text)
	rate = Column(Integer)
	loading_included = Column(Boolean, default=False)
	total_freight= Column(Integer)
	credit_period_for_balance_payment=Column(Integer)

class Shipments(base):
	__tablename__ = 'shipments'
	_id = Column(Integer, primary_key=True)
	enquiryId = Column(Integer, ForeignKey('enquiries._id'))
	bidId = Column(Integer, ForeignKey('bids._id'))
	transporterId = Column(Integer, ForeignKey('users.userId'))
	requesterId = Column(Integer, ForeignKey('users.userId'))
	tracking_status = Column(Text)
	tracking_remark = Column(Text)
	tracking_postedby = Column(Integer, ForeignKey('users.userId'))
	delivered = Column(DATE)
	timestamp = Column(TIMESTAMP)

class City(base):
	__tablename__="city"
	_id = Column(Integer, primary_key=True)
	value= Column(Text)
	label= Column(Text)

class IncludeTransporterList(base):
	__tablename__="include_transporter_list"
	_id = Column(Integer, primary_key=True)
	consignorId = Column(Integer, ForeignKey('consignor_masterdata.userId'))
	userId = Column(Integer, ForeignKey('transporter_masterdata._id'))
	userName = Column(Text)

base.metadata.create_all(bind=engine, checkfirst=True)

