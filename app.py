from flask import Flask,Response,make_response
# import flask.scaffold
# flask.helpers._endpoint_from_view_func = flask.scaffold._endpoint_from_view_func
from flask.globals import current_app
from num2words import num2words
import requests
import json
import io
from flask_restful import Api, Resource, reqparse,request
import logging, math
import urllib,random, string, time, pytz
import numpy as np
from datetime import timedelta, datetime
import pytz
import base64, jsonify
import pandas as pd
from db import *
from db_consignor import *
from db_transporter import *
from db_bids import *
from db_shipment import *
from db_consignee import *
from flask_cors import CORS, cross_origin
from pprint import pprint
from dependency import *

import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin import db

import sys
from os import environ as env
from dotenv import load_dotenv

from flask_api import status
from dictparse import DictionaryParser
from flask import Flask, request, send_file,render_template
import pdfkit

# import bcrypt
from passlib.hash import bcrypt_sha256 as sha256
import jwt
from flask_redis import FlaskRedis

from flask_jwt_extended import (
	JWTManager, jwt_required, create_access_token, get_jwt_identity,create_refresh_token
)

pd.set_option('display.max_rows', 1000)
app = Flask(__name__)
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

app.databaseURL = os.environ.get("REALTIME_FIREBASE_DATABASE_URL")

# print(app.databaseURL)
rclient = FlaskRedis(app)

app.config['JWT_SECRET_KEY'] = 'admin@123$secret@456$key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] =timedelta(days=30)
app.config['PROPAGATE_EXCEPTIONS'] = True

jwt = JWTManager(app)


#service account credentials
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate("./firebase-sdk.json")  # Ensure this file exists
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://tran-app-bded3-default-rtdb.firebaseio.com'  # Update with your actual database URL
        })
except Exception as e:
    print(f"Error initializing Firebase: {str(e)}")
#delete all firebase users
# for user in auth.list_users().iterate_all():
#     print("Deleting user " + user.uid)
#     auth.delete_user(user.uid)

CORS(app, support_credentials=True)
api = Api(app, prefix='/api')

rclient = FlaskRedis(app)


@app.after_request
def after_request(response):
	response.headers.add('Access-Control-Allow-Origin', '*')
	response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
	response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE, OPTIONS')
	return response


class Test(Resource):
	def get(self):
		return {'hello': 'world'}

class Register(Resource):
	def post(self, *args):
		
		parser = reqparse.RequestParser()
		
		parser.add_argument('email', type=str, help='Missing param: email', required=True)
		parser.add_argument('password', type=str, help='Missing param: password', required=True)
		parser.add_argument('role',type=str, help='Missing param: role', required=True)
		parser.add_argument('contact',type=str, help='Missing param: contact', required=True)
		parser.add_argument('userName',type=str, required=True)
		parser.add_argument('companyName',type=str, required=False)
		parser.add_argument('adminName',type=str,help='Missing param: adminName', required=True)
		parser.add_argument('address',type=str, required=False)
		parser.add_argument('pincode',type=str, required=False)
		parser.add_argument('location',type=str, required=False)
		parser.add_argument('gstNumber',type=str,help='Missing param: gst number', required=False)
		parser.add_argument('panNumber',type=str, help='Missing param: pan number',required=False)

		args = parser.parse_args()

		try:
			role = args['role']
			email = args['email']
			userName = args['userName']

			print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
			
			if(role == 'consignor'):
				parser.add_argument('district',type=str, required=False)
				parser.add_argument('state',type=str, required=False)
				consignorArgs = parser.parse_args()

			if(role == 'transporter'):
				parser.add_argument('truckCount',type=int, required=False)
				parser.add_argument('managerName',type=str, required=False)
				transporterArgs = parser.parse_args()

			if(role == 'consignee'):
				parser.add_argument('consignorId',type=int, required=False)
				parser.add_argument('managerName',type=str, required=False)
				parser.add_argument('district',type=str, required=False)
				parser.add_argument('state',type=str, required=False)
				consigneeArgs = parser.parse_args()
			if(role == 'supervisor'):
				parser.add_argument('consignorId', type=int, required=True)
				parser.add_argument('userName', type=str, required=True)
				supervisorArgs=parser.parse_args()
				
			EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
			if not EMAIL_REGEX.match(email):
				output={}
				output['error'] = "Invalid email"
				return jsonify(output)

			password = args['password']
			
			# Encode password
			# password = sha256.hash("password")
			password = sha256_crypt.hash(password)
			# password = sha256_crypt.encrypt(password)
			

			exists = dbCheckUserByEmail(email)

			if(exists == None):
				uid = 0
				setFirebaseNewUser = 0
				try:
					foundinFirebase = auth.get_user_by_email(email)
					if(foundinFirebase):
						print("foundinFirebase.uid:",foundinFirebase.uid)
						auth.delete_user(foundinFirebase.uid)

						setFirebaseNewUser = 1

				# exception firebase_admin.exceptions.NotFoundError(message):
				except auth.UserNotFoundError as exc:
					# return(exc.code)
					if(exc.code == 'NOT_FOUND'):
						setFirebaseNewUser = 1
						
				if(setFirebaseNewUser == 1):

					firebaseUser = auth.create_user(
						email=email,
						email_verified=False,
						# phone_number=args['contact'],
						password=password,
						display_name=args['userName'])
						# photo_url='http://www.example.com/12345678/photo.png',)
					print('Sucessfully created new user: {0}'.format(firebaseUser.uid))
					uid = firebaseUser.uid


				insertedUserId = dbRegister(email,password,role,uid,userName)
				print('-------------------------------------')
				print(insertedUserId)
				if(insertedUserId!=None):
					#add into custom realtime database collection
					ref = db.reference('Users')
					addUser = ref.child(uid)
					addUser.set({
						'userName':args['userName'],
						'email':email,
						'contact':args['contact'],
						'role': role
					})
					# resp = json.loads(resp)
					if(role == 'consignor'):
						addAddress = dbAddConsignorAddress(insertedUserId,args['address'],args['location'],args['pincode'],consignorArgs['district'],consignorArgs['state'])
						res = dbconsignorMasterData(insertedUserId,args['userName'],args['companyName'],args['adminName'],args['email'],args['contact'],args['gstNumber'],args['panNumber'])
					elif(role == 'transporter'):
						res = dbtransporterMasterData(insertedUserId,args['userName'],args['companyName'],transporterArgs['managerName'],args['email'],args['contact'],args['address'],args['pincode'],args['location'],args['gstNumber'],args['panNumber'],transporterArgs['truckCount'])
						# print(res)
					elif(role == 'consignee'):
						res = dbconsigneeMasterData(insertedUserId,consigneeArgs['consignorId'],args['userName'],args['email'],args['contact'],args['address'],args['pincode'],args['location'],args['companyName'],args['adminName'],consigneeArgs['managerName'],args['gstNumber'],args['panNumber'],consigneeArgs['district'],consigneeArgs['state'])

					elif(role == 'supervisor'):
						res = dbsupervisorMasterData(
							insertedUserId, supervisorArgs['consignorId'], supervisorArgs['userName'], args["contact"])

					if(res != None):
						access_token = create_access_token(identity=insertedUserId)
						return jsonify(success=True,msg='User signed up successfully! Please verify...',access_token=access_token)
					else:
						output = {}
						output['success'] = False
						output['msg'] = 'Something went wrong! Try again...'
						return jsonify(output)
				else:
					return jsonify(success=False,msg='Email is already registered!')
			else:
				return jsonify(success=False,msg='Email is already registered!')
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class Confirmation(Resource):
	def post(self):
		try:
			parser = reqparse.RequestParser()
		
			parser.add_argument('email', type=str, help='Missing param: email', required=True)
			parser.add_argument('token', type=str, help='Missing param: token', required=True)
			

			# parser.add_argument('truckCount',type=int, required=False)
			args = parser.parse_args()
			resp = dbConfirmation(args['email'],args['token'])
			# resp=dbConfirmation(email_id,token)

			if(resp == 'not-verified'):
				output = {}
				output['success']=False
				output['msg'] = 'We were unable to find a valid token. Your token may have expired.'
				return jsonify(output)
			elif(resp == 'emailNotFound'):
				output = {}
				output['success']=False
				output['msg'] = 'We were unable to find a user for this token.'
				return jsonify(output)
			elif(resp == 'alreadyVerified'):
				output = {}
				output['success']=False
				output['msg'] = 'This user has already been verified. Please log in.'
				return jsonify(output)
			elif(resp == 'verified'):
				output = {}
				output['success']=True
				output['msg'] = 'This user has been verified. Please log in.'
				return jsonify(output)

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ResendConfirmation(Resource):
	def post(self):
		try:
			parser = reqparse.RequestParser()
			parser.add_argument('email', type=str, help='Missing param: email', required=True)
			args = parser.parse_args()

			resp = dbResendConfirmation(args['email'])
			if(resp == None):
				output={}
				output['success'] = False
				output['msg'] = 'We were unable to find a user with that email!'
			elif(resp == 0):
				# print('####')
				output={}
				output['success'] = False
				output['msg'] = 'This account has already been verified. Please log in.'
			else:
				output={}
				output['success'] = True
				output['msg'] = 'Verification mail sent on your email!'
			
			return jsonify(output)
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ForgotPassword(Resource):
	def post(self):
		try:
			parser = reqparse.RequestParser()
			parser.add_argument('email', type=str, help='Missing param: email (str)', required=True)
			args = parser.parse_args()

			args['email'] = args['email'].lower()

			resp = dbForgotPassword(args['email'])
			print(resp)
			if(resp == None):
				return jsonify(success=False,msg='User not registered!')

			elif(resp>0):
				userId = resp
				forgotPasswordKey = secrets.token_hex(32)
				# print(forgotPasswordKey)
				rclient.set(forgotPasswordKey,str(userId))
				rclient.expire(str(userId),86400)

				resp = dbSendResetLink(args['email'],forgotPasswordKey)

				if(resp == 'success'):
					return jsonify(success=True,msg='We have sent you an email with a link to reset your password!')

			else:
				return jsonify(success=False,msg='Please verify email before reset the password!')

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ResetPassword(Resource):
	def post(self,id:str):
		try:
			parser = reqparse.RequestParser()
			parser.add_argument('newPassword', type=str, help='Missing param: newPassword (str)', required=True)
			args = parser.parse_args()
			print(id)
			password = sha256_crypt.encrypt(args['newPassword'])
			userId = rclient.get(id) 
			rclient.delete(id)
			print(userId)
			resp = dbResetPassword(userId,password)

			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class Login(Resource):
	def post(self):
		
		parser = reqparse.RequestParser()
		parser.add_argument('email', type=str, help='Missing param: email (str)', required=True)
		parser.add_argument('password', type=str, help='Missing param: password (str)', required=True)
		args = parser.parse_args()

		try:
			email = args['email'].strip()
			password = args['password']

			resp = dbLogin(email)
			print("resp:",resp)
			if(resp == None):
				return jsonify(message="Invalid email or password")
			elif(resp == 'notVerified'):
				return jsonify(success=False,message="Verify your account before login!")
			else:
				verify = json.loads(resp)
				print("verify_userId", verify[0]['userId'])

				flag = sha256_crypt.verify(password, verify[0]['password'])
				if(flag==True):
					access_token = create_access_token(identity=verify[0]['userId'])
					refresh_token = create_refresh_token(identity=verify[0]['userId'])
					return jsonify(access_token=access_token,refresh_token=refresh_token,role=verify[0]['role'])
				else:
					return jsonify(message="Invalid username or password")

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}

def valid_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise (msg)

class Enquiry(Resource):
	@jwt_required()
	def post(self):
		
		parser = reqparse.RequestParser()
		parser.add_argument('toConsigneeId', type=int, help='Missing param: toConsigneeId', required=True)
		parser.add_argument('pickupAddresssId', type=int, help='Missing param: pickupAddresssId', required=True)
		parser.add_argument('weight', type=str, help='Missing param: weight', required=True)
		parser.add_argument('truckType', type=str, help='Missing param: truckType', required=True)
		parser.add_argument('material', type=str, help='Missing param: material', required=True)
		parser.add_argument('unloadingExpense', type=int, help='Missing param: unloadingExpense', required=True)
		parser.add_argument('loadingExpense', type=int, help='Missing param: loadingExpense', required=True)
		parser.add_argument('loadingTime', type=valid_date, help='Missing param: loadingTime', required=True)
		parser.add_argument('advance', type=int, help='Missing param: advance', required=False)
		parser.add_argument('againstBill', type=int, help='Missing param: againstBill', required=False)
		parser.add_argument('remarks', type=str, help='Missing param: remarks', required=True)
		parser.add_argument('selectedTransporters', type=int,  action='append', help='Missing param: transporters list', required=True)

		args = parser.parse_args()

		print(args['selectedTransporters'])
		try:
			current_identity = get_jwt_identity()
			resp = dbPostEnquiry(current_identity,args['toConsigneeId'],args['pickupAddresssId'],args['weight'],args['truckType'],args['material'],args['unloadingExpense'],args['loadingExpense'],args['loadingTime'],args['advance'],args['againstBill'],args['remarks'],args['selectedTransporters'])

			if resp=="success":
				value = pushnotification(
					args['selectedTransporters'], current_identity, args['toConsigneeId'])
				return value
			else:
				pass 
			return resp
			 
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400
	
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()
			resp = dbEnquiryData(current_identity)
			print("current_identity:",current_identity)
			if(resp == None):
				return []
			return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class SingleEnquiryData(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()
			print("current_identity:",current_identity)
			enquiryId = request.args.get("enquiryId")
			resp = dbEnquiryDataById(enquiryId,current_identity)
			return resp
			#consignor fid,consignee firebase id
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TranporterEnquiryInfo(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()
			resp = dbTransporterEnquiryData(current_identity)
			return(resp)
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TransporterEnquiryList(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()
			resp = dbTransporterAllEnquiryData(current_identity)
			return(resp)
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TranporterEnquiryInfoById(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()
			enquiryId = request.args.get("enquiryId")
			resp = dbTransporterEnquiryDataById(current_identity,enquiryId)
			return(resp)
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsignorAddress(Resource):
	@jwt_required()
	def post(self):

		parser = reqparse.RequestParser()
		parser.add_argument('addressDict', type=dict, help='Missing param: address list', action="append", required=True)
		args = parser.parse_args()
		
		try:
			current_identity = get_jwt_identity()
			resp = dbConsignorAddressAdd(current_identity,args['addressDict'])
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

	@jwt_required()
	def put(self):

		parser = reqparse.RequestParser()
		parser.add_argument('addressDict', type=dict, help='Missing param: address list', action="append", required=True)
		args = parser.parse_args()
		
		try:
			current_identity = get_jwt_identity()
			resp = dbConsignorAddressUpdate(current_identity,args['addressDict'])
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()

			resp = dbConsignorAddressData(current_identity)
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsignorAccount(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()

			resp = dbConsignorAcount(current_identity)
			if(resp == None):
				return jsonify(success=False,msg='Consignor profile not found!')
			else:
				return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsignorCompanyList(Resource):
	@jwt_required()
	def get(self):
		try:
			resp = dbCompanyList()
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsignorAccountDetails(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()

			resp = dbConsignorAcountDetails(current_identity)
			if(resp == None):
				return jsonify(success=False,msg='Consignor profile not found!')
			else:
				return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsigneeList(Resource):
	@jwt_required()
	def get(self):
		try: 
			current_identity = get_jwt_identity()
			print("check:",current_identity)
			resp = dbConsigneeList(current_identity)
			if(resp == None):
				return jsonify(success=False,msg='Consignor profile not found!')
			else:
				return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsignorList(Resource):
	def get(self):
		try: 
			resp = dbConsignorList()
			if(resp == None):
				return jsonify(success=False,msg='Consignor not found!')
			else:
				return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class Consignee(Resource):
	@jwt_required()
	def put(self,consignee_master_id:int):
		
		parser = reqparse.RequestParser()

		parser.add_argument('contact',type=str, help='Missing param: contact', required=True)
		parser.add_argument('userName',type=str,help='Missing param: user name', required=True)
		parser.add_argument('companyName',type=str, help='Missing param: company name',required=True)
		parser.add_argument('adminName',type=str,help='Missing param: admin name', required=True)
		parser.add_argument('managerName',type=str,help='Missing param: manager name', required=True)
		parser.add_argument('address',type=str,help='Missing param: address', required=True)
		parser.add_argument('pincode',type=str,help='Missing param: pincode', required=True)
		parser.add_argument('location',type=str,help='Missing param: Location', required=True)
		parser.add_argument('panNumber',type=str,help='Missing param: PAN Number', required=True)
		parser.add_argument('gstNumber',type=str, help='Missing param: GST Number', required=True)
		parser.add_argument('district',type=str, help='Missing param: district', required=True)
		parser.add_argument('state',type=str, help='Missing param: state', required=True)

		args = parser.parse_args()

		try:
			current_identity = get_jwt_identity()
			resp = dbConsigneeUpdate(current_identity,consignee_master_id,args['contact'],args['userName'],args['companyName'],args['adminName'],args['managerName'],args['address'],args['pincode'],args['location'],args['panNumber'],args['gstNumber'],args['district'],args['state'])
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

	@jwt_required()
	def delete(self,consignee_master_id:int):
		try:
			current_identity = get_jwt_identity()
			resp = dbDeleteConsignee(current_identity,consignee_master_id)
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400
			
class addConsigneeByConsignor(Resource):
	@jwt_required()
	def post(self,session=None):
		
		current_identity = get_jwt_identity()
		parser = reqparse.RequestParser()
		
		parser.add_argument('email', type=str, help='Missing param: email', required=True)
		parser.add_argument('password', type=str, help='Missing param: password', required=True)
		parser.add_argument('contact',type=str, help='Missing param: contact', required=True)
		parser.add_argument('userName',type=str,help='Missing param: user name', required=True)
		parser.add_argument('companyName',type=str, help='Missing param: company name',required=True)
		parser.add_argument('adminName',type=str,help='Missing param: admin name', required=True)
		parser.add_argument('managerName',type=str,help='Missing param: manager name', required=True)
		parser.add_argument('address',type=str,help='Missing param: address', required=True)
		parser.add_argument('pincode',type=str,help='Missing param: pincode', required=True)
		parser.add_argument('location',type=str,help='Missing param: Location', required=True)
		parser.add_argument('panNumber',type=str,help='Missing param: PAN Number', required=True)
		parser.add_argument('gstNumber',type=str, help='Missing param: GST Number', required=True)
		parser.add_argument('district',type=str, help='Missing param: district', required=True)
		parser.add_argument('state',type=str, help='Missing param: state', required=True)
		
		args = parser.parse_args()

		try:
			role = 'consignee'
			email = args['email']
			userName = args['userName']

			EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
			if not EMAIL_REGEX.match(email):
				return jsonify(success=False,msg='Invalid email')

			
			password = args['password']
			
			# Encode password
			# password = sha256.hash("password")
			password = sha256_crypt.hash(password)

			# password = sha256_crypt.encrypt(password)

			exists = dbCheckUserByEmail(email)

			if(exists == None):
				uid = 0
				setFirebaseNewUser = 0
				try:
					foundinFirebase = auth.get_user_by_email(email)
					if(foundinFirebase):
						print(foundinFirebase.uid)
						auth.delete_user(foundinFirebase.uid)

						setFirebaseNewUser = 1

				# exception firebase_admin.exceptions.NotFoundError(message):
				except auth.UserNotFoundError as exc:
					# return(exc.code)
					if(exc.code == 'NOT_FOUND'):
						setFirebaseNewUser = 1
						
				if(setFirebaseNewUser == 1):

					firebaseUser = auth.create_user(
						email=email,
						email_verified=False,
						# phone_number=args['contact'],
						password=password,
						display_name=args['userName'])
						# photo_url='http://www.example.com/12345678/photo.png',)
					print('Sucessfully created new user: {0}'.format(firebaseUser.uid))
					uid = firebaseUser.uid


				insertedUserId = dbRegister(email,password,role,uid,userName)
				print('-------------------------------------')
				print("New consignee:",insertedUserId)


				if(insertedUserId!=None):
					#add into custom realtime database collection
					ref = db.reference('Users')
					addUser = ref.child(uid)
					addUser.set({ 
						'userName':args['userName'],
						'email':email,
						'contact':args['contact'],
						'role': role
					})

					addByConsignor = current_identity
					res = dbconsigneeMasterData(insertedUserId,current_identity,args['userName'],args['email'],args['contact'],args['address'],args['pincode'],args['location'],args['companyName'],args['adminName'],args['managerName'],args['gstNumber'],args['panNumber'],args['district'],args['state'],addByConsignor)
					print(res)
					if(res != None or res !=0):
						return jsonify(success=True,msg='User signed up successfully!')

					else:
						return jsonify(success=False,msg='Something went wrong! Try again...')
				else:
					return jsonify(success=False,msg='Email is already registered')
			else:
				addByConsignor = current_identity
				resp = checkConsigneeId(current_identity,email)
				if not resp:
					Data=json.loads(dbCheckUserByEmail(args['email']))
					res = dbconsigneeMasterData(Data[0]["userId"],current_identity,args['userName'],args['email'],args['contact'],args['address'],args['pincode'],args['location'],args['companyName'],args['adminName'],args['managerName'],args['gstNumber'],args['panNumber'],args['district'],args['state'],addByConsignor)
					if(res != None or res !=0):
						return jsonify(success=True,msg='Consignee Added!')

				return jsonify(success=False,msg='Consignee Email already added!')

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400


class TransporterAddRoutes(Resource):
	@jwt_required()
	def post(self):
		current_identity = get_jwt_identity()
		parser = reqparse.RequestParser()
		parser.add_argument('transporterRoutes', type=dict, action="append", help='Missing param: routes', required=True)
		args = parser.parse_args()
		try:
			resp = dbTransporterAddRoutes(current_identity,args['transporterRoutes'])
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TransporterUpdateRoutes(Resource):
	@jwt_required()
	def post(self):
		
		current_identity = get_jwt_identity()

		parser = reqparse.RequestParser()
		parser.add_argument('transporterRoutes', type=dict, action="append", help='Missing param: routes', required=True)
		args = parser.parse_args()
		try:
			resp = dbTransporterUpdateRoutes(current_identity,args['transporterRoutes'])
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TransporterAccount(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()
			resp = dbTransporterAccount(current_identity)
			return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TransporterList(Resource):
	@jwt_required()
	def get(self,to_route=str,from_route=str):
		try:
			current_identity = get_jwt_identity()
			resp = dbTransporterList(current_identity,to_route,from_route)
			return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TrucktypeList(Resource):
	@jwt_required()
	def get(self):
		try:
			resp = dbTruckTypeList()
			return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400



class TransporterBids(Resource):
	@jwt_required()
	def post(self):
		
		identity = get_jwt_identity()

		parser = reqparse.RequestParser()
		parser.add_argument('enquiryId', type=int, help='Missing param: enquiryId', required=True)
		parser.add_argument('advance', type=int, help='Missing param: advance', required=True)
		parser.add_argument('againstBill', type=int, help='Missing param: againstBill', required=True)
		parser.add_argument('pickup', type=valid_date, help='Missing param: pickup', required=True)
		parser.add_argument('estimatedDelivery', type=valid_date, help='Missing param: estimatedDelivery', required=True)
		parser.add_argument('remarks', type=str, help='Missing param: remarks', required=True)
		parser.add_argument('bid_rate_type', type=str,help='Missing param: bid_rate_type', required=True)
		parser.add_argument('rate', type=int,help='Missing param: rate', required=True)
		parser.add_argument('loading_included', type=bool,help='Missing param: loading included', required=True)
		parser.add_argument('total_freight', type=int,help='Missing param: total freight', required=False)
		parser.add_argument('credit_period_for_balance_payment', type=int,help='Missing param: credit period for balance payment', required=False)

		args = parser.parse_args()

		try:
			bidStatus = 'pending'
			resp = dbPostbid(identity, args['enquiryId'], args['advance'], args['againstBill'], args['pickup'],
			                 args['estimatedDelivery'], args['remarks'], args['bid_rate_type'], args['rate'], args['loading_included'], args["total_freight"], args["credit_period_for_balance_payment"], bidStatus)
			# if(resp == 0):
			# 	return jsonify(success=False,msg='You have already submitted your bid for this consignment!')
			# print(f"Data of the output {resp}")
			if(resp == None):
				return jsonify(success=False,msg='Something went wrong!')
			elif(resp == "Bid already accepted"):
				return jsonify(success=False, msg='Bid already accepted')
			elif(resp == "Data saved"):
				cc = bidpushnotification(args['enquiryId'],identity,"revised")
				return jsonify(success=True, msg='Bid updated successfully! ',msg1=f'Bid updated successfully and the notification status is {cc}')
			else:
				cc = bidpushnotification(args['enquiryId'], identity, "normal")
				return jsonify(success=True, msg='Bid submitted successfully!',msg1=f'Bid submitted successfully and the notification status is {cc}')

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

	@jwt_required()
	def get(self):
		try:
			resp = dbTransporterBidsList()
			return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TransporterBidByEnquiryId(Resource):
	@jwt_required()
	def get(self,enquiryId:int):
		try:
			resp = dbTransporterBidsByEnqId(enquiryId)
			if resp:
				return resp
			# else:
			# 	return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TransporterBidsEnqId(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = get_jwt_identity()
			resp = dbTransporterBidEnqId(userId)
			return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class SingleTransporterBidDetails(Resource):
	@jwt_required()
	def get(self,bidId:int):
		try:
			resp = dbTransporterBidDetails(bidId)
			if(resp == None):
				return jsonify(success=False,msg='No data found!')
			else:
				return resp
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class AcceptBid(Resource):
	@jwt_required()
	def post(self):
		
		identity = get_jwt_identity()

		parser = reqparse.RequestParser()
		parser.add_argument('bidId', type=int, help='Missing param: bidId', required=True)
		parser.add_argument('remarks', type=str, help='Missing param: remarks', required=True)
		args = parser.parse_args()

		try:
			resp = dbAcceptbid(identity,args['bidId'],args['remarks'])
			
			if(resp == None):
				return jsonify(success=False,msg='Bid not found!')
			elif(resp == 'accepted'):
				return jsonify(success=False,msg='Bid is already accepted!')
			if(resp == 0):
				return jsonify(success=False,msg='Something went wrong!')
			else:
				send_notification = bidAcceptedNotification(args["bidId"])
				return jsonify(success=True, msg='Bid accepted !',msg1=f'Bid accepted and the notification status code is {send_notification}')

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class RejectBid(Resource):
	@jwt_required()
	def post(self):
		
		identity = get_jwt_identity()

		parser = reqparse.RequestParser()
		parser.add_argument('bidId', type=int, help='Missing param: bidId', required=True)
		parser.add_argument('remarks', type=str, help='Missing param: remarks', required=True)
		args = parser.parse_args()

		try:
			resp = dbRejectbid(identity,args['bidId'],args['remarks'])
			if(resp == 1):
				return jsonify(success=True,msg='Bid rejected successfully!')
			elif(resp == None):
				return jsonify(success=False,msg='Bid not found!')
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ShipmentUpdate(Resource):
	@jwt_required()
	def post(self):
		
		identity = get_jwt_identity()

		parser = reqparse.RequestParser()
		parser.add_argument('status', type=str, help='Missing param: status', required=True)
		parser.add_argument('remark', type=str, help='Missing param: remark', required=True)
		parser.add_argument('shipmentId', type=int, help='Missing param: shipmentId', required=True)
		args = parser.parse_args()

		try:
			resp,data = dbShipmentUpdate(identity,args['status'],args['remark'],args['shipmentId'])
			
			if(resp == 1):
				if data!="Not Delivered":
					send_notification = sendEmailNotifiction(
						data[0]["email"], data[0]["material"], data[0]["weight"], data[0]["truckType"], data[0]["userName"], data[0]["companyName"])
					print("send_notification:", send_notification)
					if send_notification == "success":
						return jsonify(success=True, msg='Shipment delivered and notification sent !')
				return jsonify(success=True,msg="Shipment tracking updated!")
			elif(resp == None):
				return jsonify(success=False,msg="Shipment not found!")
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ShipmentComplete(Resource):
	@jwt_required()
	def post(self):
		
		identity = get_jwt_identity()

		parser = reqparse.RequestParser()
		parser.add_argument('remark', type=str, help='Missing param: remark', required=True)
		parser.add_argument('shipmentId', type=int, help='Missing param: shipmentId', required=True)
		args = parser.parse_args()

		try:
			resp,data = dbShipmentComplete(identity,args['remark'],args['shipmentId'])
			if(resp == 1):
				if data:
					send_notification = sendEmailNotifiction(
						data[0]["email"], data[0]["material"], data[0]["weight"], data[0]["truckType"], data[0]["userName"], data[0]["companyName"])
					print("send_notification:", send_notification)
					if send_notification=="success":
						return jsonify(success=True,msg='Shipment delivered and notification sent !')
					return jsonify(success=True,msg='Shipment delivered!')
			elif(resp == None):
				return jsonify(success=False,msg='Shipment not found!')
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ShipmentDetails(Resource):
	
	@jwt_required()
	def post(self):
		
		identity = get_jwt_identity()

		parser = reqparse.RequestParser()
		parser.add_argument('shipmentId', type=int, help='Missing param: shipmentId', required=True)
		args = parser.parse_args()

		try:
			resp = dbShipmentData(args['shipmentId'])
		
			if(resp == None):
				return jsonify(success=False,msg='Shipment not found!')
			else:
				return resp
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ShipmentforConsignor(Resource):
	@jwt_required()
	def post(self):
		try:
			identity = get_jwt_identity()
			resp = dbShipmentforConsignor(identity)
		
			if(resp == None):
				return jsonify(success=False,msg='Shipment not found!')
			else:
				return resp
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ShipmentforTransporter(Resource):
	@jwt_required()
	def post(self):
		try:
			identity = get_jwt_identity()

			resp = dbShipmentforTransporter(identity)
		
			if(resp == None):
				return jsonify(success=False,msg='Shipment not found!')
			else:
				return resp
			
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsigneeAccount(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = get_jwt_identity()
			resp = dbConsigneeAccount(userId)
			print(resp)
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class EnquiryDataForConsignee(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = get_jwt_identity()
			resp = dbEnquiryDataForConsignee(userId)
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ShipmentDataForConsignee(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = get_jwt_identity()
			resp = dbShipmentDataForConsignee(userId)
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class TransporterProfile(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = get_jwt_identity()
			resp = dbTransporterProfileDetails(userId)
			pprint(resp)
			if(resp == None):
				return ({'success':False,'msg':'Profile data not found!'}),400
			else:
				return(resp)

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

	@jwt_required()
	def put(self):
		try:
			userId = get_jwt_identity()

			parser = reqparse.RequestParser()
			parser.add_argument('companyName', type=str, help='Missing param: companyName', required=True)
			parser.add_argument('userName', type=str, help='Missing param: userName', required=True)
			parser.add_argument('address', type=str, help='Missing param: address', required=True)
			parser.add_argument('truckCount', type=str, help='Missing param: truckCount', required=True)
			parser.add_argument('panNumber', type=str, help='Missing param: panNumber', required=True)
			parser.add_argument('gstNumber', type=str, help='Missing param: gstNumber', required=True)

			args = parser.parse_args()

			resp = dbTransporterProfileUpdate(userId,args['companyName'],args['userName'],args['address'],args['truckCount'],args['panNumber'],args['gstNumber'])
			
			if(resp == None):
				return ({'success':False,'msg':'Transporter record not found!'}),400
			else:
				return jsonify(success=True,msg='Profile updated successfully!')

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsignorProfile(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = get_jwt_identity()
			resp = dbConsignorProfileDetails(userId)

			if(resp == None):
				return ({'success':False,'msg':'Profile data not found!'}),400
			else:
				return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400
	
	@jwt_required()
	def put(self):
		try:
			userId = get_jwt_identity()

			parser = reqparse.RequestParser()
			parser.add_argument('companyName', type=str, help='Missing param: companyName', required=True)
			parser.add_argument('userName', type=str, help='Missing param: userName', required=True)
			parser.add_argument('panNumber', type=str, help='Missing param: panNumber', required=True)
			parser.add_argument('gstNumber', type=str, help='Missing param: gstNumber', required=True)
			parser.add_argument('address', type=str, help='Missing param: address', required=True)
			parser.add_argument('location', type=str, help='Missing param: location', required=True)
			parser.add_argument('district', type=str, help='Missing param: district', required=True)
			parser.add_argument('state', type=str, help='Missing param: state', required=True)
			parser.add_argument('pincode', type=int, help='Missing param: pincode', required=True)
	
			args = parser.parse_args()

			resp = dbConsignorProfileUpdate(userId,args['companyName'],args['userName'],args['panNumber'],args['gstNumber'],args['address'],args['location'],args['district'],args['state'],args['pincode'])
			
			if(resp == None):
				return ({'success':False,'msg':'Consignor record not found!'}),400
			else:
				return jsonify(success=True,msg='Profile updated successfully!')

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ConsigneeProfile(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = get_jwt_identity()
			resp = dbConsigneeProfileDetails(userId)

			if(resp == None):
				return ({'success':False,'msg':'Profile data not found!'}),400
			else:
				return jsonify(profile=resp)

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

	@jwt_required()
	def put(self):
		try:
			userId = get_jwt_identity()

			parser = reqparse.RequestParser()
			parser.add_argument('companyName', type=str, help='Missing param: companyName', required=True)
			parser.add_argument('userName', type=str, help='Missing param: userName', required=True)
			parser.add_argument('address', type=str, help='Missing param: address', required=True)
			parser.add_argument('panNumber', type=str, help='Missing param: panNumber', required=True)
			parser.add_argument('gstNumber', type=str, help='Missing param: gstNumber', required=True)

			args = parser.parse_args()

			resp = dbConsigneeProfileUpdate(userId,args['companyName'],args['userName'],args['address'],args['panNumber'],args['gstNumber'])
			
			if(resp == None):
				return ({'success':False,'msg':'Consignee record not found!'}),400
			else:
				return jsonify(success=True,msg='Profile updated successfully!')

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400

class ChangePassword(Resource):
	@jwt_required()
	def put(self):
		try:
			userId = get_jwt_identity()

			parser = reqparse.RequestParser()
			parser.add_argument('oldPassword', type=str, help='Missing param: oldPassword', required=True)
			parser.add_argument('newPassword', type=str, help='Missing param: newPassword', required=True)

			args = parser.parse_args()

			resp = dbCheckUser(userId)
			
			if(resp == None):
				return jsonify(message="Invalid email or password!")
			else:
				verify = json.loads(resp)
				# print(verify)

				flag = sha256_crypt.verify(args['oldPassword'], verify[0]['password'])

				if(flag==True):
					newPassword = sha256_crypt.encrypt(args['newPassword'])
					opt = dbChangePassword(userId,newPassword)
					if(opt == 'success'):
						return jsonify(success=True,msg='Password changed successfully!')
				else:
					return ({'success':False,'msg':'Invalid old password!'}),400

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success':False,'message':'Something went wrong!'}),400


class SingleEnquiryDelete(Resource):
	@jwt_required()
	def post(self):
		try:
			parser = reqparse.RequestParser()
			parser.add_argument('enquiry_id', type=str, help='Missing param: Enquiry Id', required=True)
			current_identity = get_jwt_identity()
			args = parser.parse_args()
			enquiry_id = args["enquiry_id"]
			resp = dbChangeEnquiryStatus(current_identity, enquiry_id)
			if(resp == None):
				return []
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400

class SaveFCMToken(Resource):
	@jwt_required()
	def post(self):
		try:
			parser = reqparse.RequestParser()
			parser.add_argument('token', type=str,help='Missing param:FCM Token', required=True)
			current_identity = get_jwt_identity()
			args = parser.parse_args()
			token = args["token"]
			print(current_identity,token)
			resp = dbregisterfcmtoken(current_identity,token)
			if(resp == None):
				return []
			return resp

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400


class MessagePushNotification(Resource):
	@jwt_required()
	def post(self):
		try:
			parser = reqparse.RequestParser()
			parser.add_argument('sendMessage', type=str,help='Missing param:Message', required=True)
			parser.add_argument('firebase_id', type=str, help='Firebase Id', required=True)
			parser.add_argument('sender_name', type=str,help='Missing param:Sender Name', required=True)
			
			args = parser.parse_args()

			resp = messageNotification(
				args['sendMessage'], args['firebase_id'], args['sender_name'])
			
			if(resp == None):
					return []
			elif resp==200:
				return {'success': True, 'message': 'Sent Notification!'}
			else:
				return ({'success': False, 'message': 'Something went wrong!'}), 400

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400


class SupervisorList(Resource):
	@jwt_required()
	def get(self):
		try:
			current_identity = get_jwt_identity()
			print("check:",current_identity)
			respData = dbsupervisorList(current_identity)
			print("RESP: ", respData)
			if(respData == None):
				return []
			else:
				return respData

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400
		

class UpdateSupervisor(Resource):
	@jwt_required()
	def post(self):
		try:
			current_identity = get_jwt_identity()
			parser = reqparse.RequestParser()
			parser.add_argument('supervisor_id', type=int,help='Missing param:supervisor_id', required=True)
			parser.add_argument('supervisorUserId', type=int,help='Missing param:supervisorUserId', required=True)
			parser.add_argument('email', type=str, help='Missing param:email', required=False)
			parser.add_argument('role', type=str, help='Missing param:role', required=False)
			parser.add_argument('userName', type=str,help='Missing param:userName', required=False)
			parser.add_argument('contact', type=str,help='Missing param:contact', required=False)
			args = parser.parse_args()

			print("check:", current_identity)
			respData = updateSupervisor(args["supervisor_id"],args["supervisorUserId"],args["email"],args["userName"],args["contact"])
			if(respData == None):
				return []
			else:
				return respData

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400
		
class AddCities(Resource):
	@retry_db((OperationalError,StatementError),n_retries=30)
	@mk_session
	def get(self, session=None):
		try:
			q = session.query(City).with_entities(City.value,City.label).statement
			df = pd.read_sql(q, engine)
			data = df.to_json(orient="records")
			data = json.loads(data)
			return data
		
		except exc.SQLAlchemyError as err:
			error = str(err.__dict__['orig'])
			print("error:"+error)

	@jwt_required()
	@retry_db((OperationalError,StatementError),n_retries=30)
	@mk_session
	def post(self, session=None):
		try:
			parser = reqparse.RequestParser()
			parser.add_argument('value', type=str, help='Missing param:value', required=True)
			parser.add_argument('label', type=str, help='Missing param:label', required=True)
			args = parser.parse_args()

			q=session.query(City).with_entities(City.value,City.label).filter(or_(City.value==args["value"],City.label==args["label"])).statement
			df = pd.read_sql(q, engine)
			data = df.to_json(orient="records")
			data = json.loads(data)

			if data ==[]:
				insertCity=City(value=args["value"],label=args["label"])
				session.add(insertCity)
				session.commit()
				return "Data Saved!"

			else:
				return "Data already present!"

		except exc.SQLAlchemyError as err:
			error = str(err.__dict__['orig'])
			print("error:"+error)

class AllTranporterList(Resource):
	@jwt_required()
	@retry_db((OperationalError,StatementError),n_retries=30)
	@mk_session
	def get(self,session=None):
		try:
			q = session.query(TransporterMasterData).with_entities(TransporterMasterData._id,TransporterMasterData.userId,TransporterMasterData.userName,TransporterMasterData.companyName,TransporterMasterData.address).statement
			df = pd.read_sql(q, engine)
			if df.empty:
				return "No Transporter available."
			
			data = df.to_json(orient="records")
			data = json.loads(data)
			return data
		
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400
	@jwt_required()
	def post(self):
		try:
			current_identity = get_jwt_identity()
			parser = reqparse.RequestParser()
			parser.add_argument('data_list', type=dict, action='append')
			args = parser.parse_args()
			respData = updateIncludeList(args['data_list'],current_identity)
			return respData
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400
	
class SelectedTransporterId(Resource):
	@jwt_required()
	@retry_db((OperationalError,StatementError),n_retries=30)
	@mk_session
	def get(self,session=None):
		try:
			current_identity = get_jwt_identity()
			print("cccc:",current_identity)
			q = session.query(IncludeTransporterList).with_entities(IncludeTransporterList.userId.label("_id")).filter(IncludeTransporterList.consignorId  == current_identity).statement
			df = pd.read_sql(q, engine)
			if df.empty:
				return {'Data':[] , 'message': "No data available!"}
			else:
				data = df.to_json(orient="records")
				data = json.loads(data)
				return {'Data':data,'message':"success"}
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400
		
class TransporterAllRoutes(Resource):
	@jwt_required()
	def get(self):
		try:
			userId = request.args.get("user_id")
			respData = dbTransporterroutes(userId)
			return respData
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400


class GeneratePdf(Resource):
	@jwt_required()
	def get(self):
		#for server 
		wkhtmltopdf='/home/tranapp/wkhtmltopdf-download/wkhtmltox/bin/wkhtmltopdf'
		#for local
		# wkhtmltopdf='C:\Program Files\wkhtmltopdf\\bin\wkhtmltopdf.exe'
		shipment_id = request.args.get('shipmentId')
		Data=dbShipmentData(shipment_id)
		dt_utc = datetime.fromtimestamp(Data["shipment"][0]["timestamp"]/ 1000, tz=pytz.utc)
		date_time = dt_utc.strftime("%Y-%m-%d %H:%M:%S")

		# print("checking:",Data["Bids"][0]["loading_included"])

		total_amount="{:,}".format((Data["Bids"][0]["againstBill"])+(Data["Bids"][0]["advance"]))
		consignee_name= Data["toAddress"][0]["userName"]
		consignor_name= Data["requester"][0]["userName"]

		# print("DDDD:",Data["toAddress"][0]["userName"])
		
		if Data["Bids"][0]["loading_included"]:
			hamali= 0
			int_total=Data["Bids"][0]["againstBill"]
			Total="{:,}".format(int_total)
		else:
			int_total=(Data["Bids"][0]["againstBill"])+(Data["enquiry"][0]["unloadingExpense"])+(Data["enquiry"][0]["loadingExpense"])
			hamali= "{:,}".format((Data["enquiry"][0]["unloadingExpense"])+(Data["enquiry"][0]["loadingExpense"]))
			Total="{:,}".format(int_total)
		
		total_in_numeric= num2words(int_total).capitalize()
		renderData={"panNumber":Data["requester"][0]["panNumber"],"gstNumber":Data["requester"][0]["gstNumber"],"transporterName":Data["transporter"][0]["companyName"],"Address":Data["toAddress"][0]["address"],"district":Data["toAddress"][0]["district"],"state":Data["toAddress"][0]["state"],"pincode":Data["toAddress"][0]["pincode"],"contact":Data["toAddress"][0]["contact"],"date":date_time,"material":Data["enquiry"][0]["material"],"weight":Data["enquiry"][0]["weight"],"advance":"{:,}".format(Data["Bids"][0]["advance"]),"rate":"{:,}".format(Data["Bids"][0]["rate"]),"hamali":hamali,"total_freight":"{:,}".format(Data["Bids"][0]["total_freight"]),"total":total_amount,"Total":Total,"consignee_name":consignee_name,"consignor_name":consignor_name,"total_in_numeric":total_in_numeric}
		rendered_template = render_template('receipt.html', renderData=renderData)
		
		
		config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf)

		pdf = pdfkit.from_string(rendered_template, False,configuration=config)
		response = make_response(pdf)
		response.headers["Content-Type"] = "application/pdf"
		response.headers["Content-Disposition"] = "inline; filename=output.pdf"
		return response




api.add_resource(Test, '/test')
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Confirmation,'/account/confirmation')
api.add_resource(ResendConfirmation,'/resend')
api.add_resource(ForgotPassword,'/forgot/password')
api.add_resource(ResetPassword, '/reset/password/<id>')
api.add_resource(ChangePassword,'/set/new/password')

api.add_resource(Enquiry,'/enquiry')
api.add_resource(SingleEnquiryDelete,'/enquiry/single/delete')
api.add_resource(SingleEnquiryData,'/enquiry/single')
api.add_resource(TranporterEnquiryInfo,'/transporter/enquiry/short')
api.add_resource(TransporterEnquiryList,'/transporter/enquiry/all')
api.add_resource(TranporterEnquiryInfoById,'/transporter/enquiry/single')
api.add_resource(ConsignorAddress,'/consignor/address')
api.add_resource(ConsignorAccount,'/consignor/account')
api.add_resource(ConsignorCompanyList,'/consignor/company/list')
api.add_resource(ConsignorAccountDetails,'/consignor/account/details')
api.add_resource(ConsigneeList,'/consignee/list')
api.add_resource(ConsignorList,'/consignor/list')
api.add_resource(Consignee,'/consignee/<consignee_master_id>')
api.add_resource(addConsigneeByConsignor,'/consignee/new')
api.add_resource(ConsignorProfile,'/consignor/profile')

#transporter api
api.add_resource(TransporterAddRoutes,'/transporter/routes/add')
api.add_resource(TransporterUpdateRoutes,'/transporter/routes/update')
api.add_resource(TransporterAccount,'/transporter/account')
api.add_resource(TransporterList,'/transporter/list/<to_route>/<from_route>')
api.add_resource(TrucktypeList,'/transporter/trucktype/list')
api.add_resource(TransporterProfile,'/transporter/profile')
api.add_resource(AllTranporterList,'/alltransporter/list')
api.add_resource(SelectedTransporterId,'/transporterid/list')
api.add_resource(TransporterAllRoutes,'/alltransporter/routes')

#bids api
api.add_resource(TransporterBids, '/bid')
api.add_resource(TransporterBidByEnquiryId, '/bid/<enquiryId>')
api.add_resource(SingleTransporterBidDetails, '/bid/details/<bidId>')
api.add_resource(AcceptBid, '/bid/accept')
api.add_resource(RejectBid, '/bid/reject')
api.add_resource(TransporterBidsEnqId,'/bid/transporter/enquiryid')

#shipment api
api.add_resource(ShipmentUpdate,'/shipment/update')
api.add_resource(ShipmentComplete,'/shipment/complete')
api.add_resource(ShipmentDetails,'/shipment/details')
api.add_resource(ShipmentforConsignor,'/shipment/consignor')
api.add_resource(ShipmentforTransporter,'/shipment/transporter')

#consignee api
api.add_resource(ConsigneeAccount,'/consignee/account')
api.add_resource(EnquiryDataForConsignee,'/consignee/enquiry/details')
api.add_resource(ShipmentDataForConsignee,'/consignee/shipment/list')
api.add_resource(ConsigneeProfile,'/consignee/profile')

api.add_resource(SaveFCMToken,'/user/fcmtoken')
api.add_resource(MessagePushNotification,'/user/pushnotification')
api.add_resource(SupervisorList,'/supervisor/list')
api.add_resource(UpdateSupervisor,'/supervisor/update')
api.add_resource(AddCities,'/city/name')

api.add_resource(GeneratePdf,"/transporter/reciept")
APP_HOST = os.environ.get("APP_HOST", "127.0.0.1")
APP_PORT = int(os.environ.get("APP_PORT", 5000))

if __name__ == '__main__':
	app.run(debug=True, host=APP_HOST, port=APP_PORT)