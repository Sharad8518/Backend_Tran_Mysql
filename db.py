from os import stat
import re
import sys
from sqlalchemy.sql.expression import update
from sqlalchemy.sql.functions import user
import models
import pandas as pd
from flask import json, jsonify
from sqlalchemy import exc
from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.sql.sqltypes import DateTime, NullType, String
from models import *
from passlib.hash import sha256_crypt
# from passlib.hash import pbkdf2_sha256 as sha256
from datetime import datetime, timedelta
import secrets


from sendgrid.helpers.mail import Mail
from sendgrid import SendGridAPIClient
from python_http_client.exceptions import HTTPError


SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
SENDGRID_DEFAULT_FROM = 'contact@tran.co.in'
TEMPLATE_ID = 'd-2fd9933e5e754877a04e196b4dafbc23'


def mk_session(fun):
	def wrapper(*args, **kwargs):
		s = session()
		kwargs['session'] = s
		try:
			res = fun(*args, **kwargs)
		except Exception as e:
			s.rollback()
			s.close()
			raise e

		s.close()
		return res
	wrapper.__name__ = fun.__name__
	return wrapper


def retry_db(exceptions, n_retries=3, ival=1):
	def decorator(fun):
		@wraps(fun)
		def wrapper(*args, **kwargs):
			exception_logged = False
			for r in range(n_retries):
				try:
					return fun(*args, **kwargs)
				except exceptions as e:
					if not exception_logged:
						print(e)
						exception_logged = True
					else:
						print("Retry #{r} after receiving exception.")

					time.sleep(ival)
			return fun(*args, **kwargs)
		return wrapper
	return decorator

#register
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbRegister( email, password, role,uid,userName, session=None):
	# print('dbRegister function')
	checkUserId = 0
	checkUser = session.query(Users).filter(Users.email== email).statement
	df = pd.read_sql(checkUser, engine)
	
	userId = df['userId'].tolist()
	# print('existUserId'+str(userId[0]))
	if(userId):
		checkUserId = userId[0]
	# print("checkedUserId"+checkUserId)
	if(checkUserId == 0):

		try:
			if role=="consignee":
				value=1
			else:
				value=0
			insertUsers = Users(role = role, email = email, password = password,isVerified = value,firebaseUid = uid, signupTimestamp = datetime.now())
			session.add(insertUsers)
			session.commit()
			insertedUserId = insertUsers.userId
			print("insertedUserId",insertedUserId)
			token = secrets.token_hex(16)
			# print("token: ",token)
			insertToken = UserTokens(_userId = insertedUserId, userToken = token, timestamp = datetime.now())
			session.add(insertToken)
			session.commit()
			if role!="consignee":
				verifyUrl = f"/verify/account-confirmation?email={email}&token={token}"
                    #  print("verifyurl:",verifyUrl)
				# verifyUrl = os.environ.get("http://127.0.0.1:5000") + 'verify/account-confirmation?email=' + email + '&token=' + token

            
                  
				try:
					# create Mail object and populate
					message = Mail(
						from_email=SENDGRID_DEFAULT_FROM,
						to_emails=email)
					# pass custom values for our HTML placeholders
					message.dynamic_template_data = {
						'email': email,
						'verifyUrl': verifyUrl,
						'userName':userName
					}

					message.template_id = TEMPLATE_ID
					sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
					response = sg.send(message)
				
				except HTTPError as e:
					print("e.to_dict: ", e.to_dict)
			
			return insertedUserId 
			
		# except exc.SQLAlchemyError as err:
		# 	print(err)
		except Exception as e:
			print(e)
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
	else:
		print("checkuserId in register:",checkUserId)
		return None

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbResendConfirmation(email,session=None):
	try:
		checkUser = session.query(Users).filter(Users.email== email).statement
		df = pd.read_sql(checkUser, engine)
		isverified = df['isVerified'].tolist()
		userId = df['userId'].tolist()
		role = df['role'].tolist()
		# print(role)
		if(role[0] == 'consignor'):
			userNameQ = session.query(ConsignorMasterData).with_entities(ConsignorMasterData.userName).filter(ConsignorMasterData.userId== userId).statement
			df = pd.read_sql(userNameQ, engine)
			userName = df['userName'].tolist()
		if(role[0] == 'consignee'):
			userNameQ = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.userName).filter(ConsigneeMasterData.userId== userId).statement
			df = pd.read_sql(userNameQ, engine)
			userName = df['userName'].tolist()
		if(role[0] == 'transporter'):
			userNameQ = session.query(TransporterMasterData).with_entities(TransporterMasterData.userName).filter(TransporterMasterData.userId== userId).statement
			df = pd.read_sql(userNameQ, engine)
			userName = df['userName'].tolist()

		# print(userName)
		if(df.empty):
			return None
		else:
			if(isverified[0]):
				return 0
			else:
				token = secrets.token_hex(16)
				print(token)
				insertToken = UserTokens(_userId = userId[0], userToken = token, timestamp = datetime.now())
				session.add(insertToken)
				session.commit()

				verifyUrl = os.environ.get("IP_URL") + 'verify/account-confirmation?email=' + email + '&token=' + token
				print(verifyUrl)

				# create Mail object and populate
				message = Mail(
					from_email=SENDGRID_DEFAULT_FROM,
					to_emails=email)
				# pass custom values for our HTML placeholders
				message.dynamic_template_data = {
					'email': email,
					'verifyUrl': verifyUrl,
					'userName':userName[0]
				}

				message.template_id = 'd-2fd9933e5e754877a04e196b4dafbc23'
				sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
				response = sg.send(message)

				return userId[0]

	# except exc.SQLAlchemyError as err:
	# 		print(err)
	except:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		return ({'success':False,'message':'Something went wrong!'}),400

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbForgotPassword(email,session=None):
	try:
		checkUser = session.query(Users).filter(Users.email== email).statement
		df = pd.read_sql(checkUser, engine)

		if(df.empty):
			return None
		else:
			isVerified = df['isVerified'].tolist()
			userId = df['userId'].tolist()
			# if(not isVerified[0]):
			# 	return 0
			# else:
			return(int(userId[0]))
				
	except exc.SQLAlchemyError as err:
		print(err)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbSendResetLink(email,forgotPasswordKey,session=None):
	try:
		link = os.environ.get("IP_URL") + 'verify/forgotPassword?token=' + forgotPasswordKey

		# create Mail object and populate
		message = Mail(
			from_email=SENDGRID_DEFAULT_FROM,
			to_emails=email)
		# pass custom values for our HTML placeholders
		message.dynamic_template_data = {
			'email': email,
			'link': link
		}

		message.template_id = 'd-cb75235118f14337879b76f050c39da4'
		sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
		response = sg.send(message)

		return 'success'

	except exc.SQLAlchemyError as err:
		print(err)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbResetPassword(userId,password,session=None):
	try:
		
		if(userId == None):
			output = {}
			output['success'] = False
			output['msg'] = 'Password reset link has expired!'
			return output
		else:
			data = {'password':password}
			update = session.query(Users).filter(Users.userId == userId).update(data)
			session.commit()
			return "success"

	# except exc.SQLAlchemyError as err:
	# 	print(err)
	except:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		return ({'success':False,'message':'Something went wrong!'}),400

#transporterMasterData
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbtransporterMasterData( userId,userName,companyName,managerName,email,contact,address,pincode,location,gstNumber,panNumber,truckCount, session=None):
	print('transporter master data')
	if(userId != 0 or userId != None):

		try:
			insertMasterData = TransporterMasterData(userId=userId,userName=userName,email=email,contact=contact,address=address,pincode=pincode,location=location,companyName=companyName,managerName=managerName,gstNumber=gstNumber,panNumber=panNumber,truckCount=truckCount,timestamp=datetime.now())
			session.add(insertMasterData)
			session.commit()
			insertId = insertMasterData._id
			return insertId
			
		except exc.SQLAlchemyError as e:
			print(e)
			exc_type,exc_obj,exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type,fname,exc_tb.tb_lineno)
	else:
		return None

#add supervisor for consignor 
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbsupervisorMasterData(insertedUserId, consignorUserId, userName, contact, session=None):
	print('transporter master data')
	if(consignorUserId != 0 or consignorUserId != None):
		try:
			print("consignorUserId", consignorUserId)
			consignor_id=session.query(ConsignorMasterData).with_entities(ConsignorMasterData._id).filter(ConsignorMasterData.userId==consignorUserId).statement 
			df = pd.read_sql(consignor_id, engine)
			consignorid=df["_id"].tolist()
			print(consignorid[0])
			insertMasterData = SupervisorMasterData(
				userId=insertedUserId, userName=userName, consignorId=consignorid[0], contact=contact, timestamp=datetime.now())
			session.add(insertMasterData)
			session.commit()
			insertId = insertMasterData._id
			return insertId
			
		except exc.SQLAlchemyError as e:
			print(e)
			exc_type,exc_obj,exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type,fname,exc_tb.tb_lineno)
	else:
		return None

#add consignor address
@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbAddConsignorAddress(userId,address,location,pincode,district,state,session=None):
	# print('add consignor address api')
	# print(district)
	# print(userId)
	
	if(userId != 0 or userId != None):
		try:
			insertAdrs = ConsignorAddress(consignorId=userId,address=address,pincode=pincode,location=location,district=district,state=state,isDefault=True,timestamp=datetime.now())
			session.add(insertAdrs)
			session.commit()
			insertId = insertAdrs._id
			return insertId
			
		except exc.SQLAlchemyError as err:
			print(err)
	else:
		return None

#consignorMasterData
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbconsignorMasterData(userId,userName,companyName,adminName,email,contact,gstNumber,panNumber,session=None):
	# print('add into consignor master data api')
	checkUserId = 0
	checkUser = session.query(Users).filter(Users.email== email).statement
	df = pd.read_sql(checkUser, engine)
	userId = df['userId'].tolist()
	if(userId):
		checkUserId = userId[0]
	if(checkUserId != 0):

		try:
			insertMasterData = ConsignorMasterData(userId=userId,userName=userName,email=email,contact=contact,companyName=companyName,adminName=adminName,gstNumber=gstNumber,panNumber=panNumber,timestamp=datetime.now())
			session.add(insertMasterData)
			session.commit()
			insertId = insertMasterData._id
			return insertId
			
		except exc.SQLAlchemyError as e:
			print(e)
			exc_type,exc_obj,exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type,fname,exc_tb.tb_lineno)
	else:
		return None

#consigneeMasterData
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbconsigneeMasterData( userId,consignorId,userName,email,contact,address,pincode,location,companyName,adminName,managerName,gstNumber,panNumber,district,state,addByConsignor,session=None):
	
	if(userId != 0):

		try:
			insertMasterData = ConsigneeMasterData(userId=userId,consignorId=consignorId,userName=userName,email=email,contact=contact,address=address,pincode=pincode,location=location,companyName=companyName,adminName=adminName,managerName=managerName,gstNumber=gstNumber,panNumber=panNumber,district=district,state=state,addByConsignor=addByConsignor,timestamp=datetime.now())
			session.add(insertMasterData)
			session.commit()
			insertId = insertMasterData._id
			print("insertId",insertId)
			if(insertId != None):
				return insertId
			else:
				return 0
			
		except Exception as e:
			print(e)
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
	else:
		return None

#check consigorId registered to the consignee
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def checkConsigneeId(current_identity,email,session=None):
	userquery = session.query(ConsigneeMasterData).filter(ConsigneeMasterData.consignorId == current_identity,ConsigneeMasterData.email==email).statement
	df = pd.read_sql(userquery, engine)
	if df.empty:
		return False
	else:
		return True



@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbConfirmation(email,token,session=None):
	try:
		
		userquery = session.query(UserTokens).filter(UserTokens.userToken == token).statement
		df = pd.read_sql(userquery, engine)
		
		if(df.empty):
			return('not-verified')
			
		else:
			userquery = session.query(Users).with_entities(Users.userId,Users.isVerified).filter(Users.email == email).statement
			user = pd.read_sql(userquery, engine)
			isverified = user['isVerified'].tolist()
			# print(isverified[0])

			if(user.empty):
				return('emailNotFound')
			elif(isverified[0]):
				return('alreadyVerified')
			else:
				data = {'isVerified' : True}
				updateAssets = session.query(Users).filter(Users.email== email).update(data)
				session.commit()
				return('verified')
	
	except Exception as e:
		print(e)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)

#login
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbLogin(email,session=None):
	try:
		userquery = session.query(Users).with_entities(Users.userId,Users.email, Users.password,Users.role).filter(Users.email == email).statement
		df = pd.read_sql(userquery, engine)

		isVerified = session.query(Users).filter(and_(Users.email == email),(Users.isVerified==1),(Users.status==1)).scalar()
		
		if(df.empty):
			return None
		if(isVerified == None):
			return('notVerified')
		if not df.empty:
			userid = df["userId"].tolist()
			print("check_consignor_df:", userid)
			check_consignor = session.query(ConsignorMasterData, SupervisorMasterData, Users).with_entities(Users.userId.label("supervisor_user_id"), Users.email, Users.password, Users.role, ConsignorMasterData.userId,Users.isVerified).filter(
				SupervisorMasterData.userId == Users.userId, ConsignorMasterData._id == SupervisorMasterData.consignorId, Users.email == email).statement
			check_consignor_df = pd.read_sql(check_consignor, engine)
			print("QWERTY:", check_consignor_df.to_json(orient="records"))
			if(not check_consignor_df.empty):
				return check_consignor_df.to_json(orient="records")
			else:
				return df.to_json(orient="records")
		
	except exc.SQLAlchemyError as err:
		print(err)

#post enquiry
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbPostEnquiry(enquiryBy,toConsigneeId,pickupAddresssId,weight,truckType,material,unloadingExpense,loadingExpense,loadingTime,advance,againstBill,remarks,selectedTransporters,session=None):
			
	try:
		
		query = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.userId).filter(ConsigneeMasterData._id== toConsigneeId).statement
		df = pd.read_sql(query, engine)
		consigneeId = df['userId'].tolist()
		insertEnquiry = Enquiry(enquiryBy = enquiryBy, toConsigneeId = consigneeId[0], pickupAddresssId = pickupAddresssId, weight = weight, truckType = truckType, material = material, unloadingExpense = unloadingExpense,loadingExpense=loadingExpense,loadingTime = loadingTime, advance = advance, againstBill = againstBill, remarks = remarks, timestamp = datetime.now())
		session.add(insertEnquiry)
		session.commit()
	
		# print(len(selectedTransporters))
		if(insertEnquiry._id):
			if(len(selectedTransporters)>0 ):
				for t in selectedTransporters:
					addSelectedTransporters = SelectedTransporter(enquiryId = insertEnquiry._id, selectedTransporterId = int(t))
					session.add(addSelectedTransporters)
					session.commit()

					if(not addSelectedTransporters):
						return 'addSelectedTransporterError'
		return('success')
		
	# except exc.SQLAlchemyError as err:
	# 	error = str(err.__dict__['orig'])
	# 	#   return error
	# 	print("error:"+error)
	except Exception as e:
		print(e)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)

#get short enquiry data
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbEnquiryData(userId,session=None):
	try:
		# enquiryQuery = session.query(Enquiry).filter(
		# 	Enquiry.enquiryBy == userId, Enquiry.enquirystatus == 0).order_by(Enquiry.timestamp.desc()).outerjoin(Shipments, Shipments.enquiryId == Enquiry._id).statement
		#enquiryQuery = """select enq._id,enq.enquiryBy,enq.toConsigneeId,enq.pickupAddresssId,enq.weight,enq.truckType,enq.material,enq.unloadingExpense,enq.loadingExpense,enq.loadingTime,enq.advance,enq.againstBill,enq.remarks,enq.timestamp,enq.enquirystatus,tran.shipments.tracking_status,tran.shipments.delivered,tran.bids.status from tran.enquiries as enq left join tran.shipments on shipments.enquiryId=enq._id left join tran.bids on tran.bids.enquiryId=enq._id where enq.enquiryBy={} and enq.enquirystatus=0 group by enq._id order by enq._id desc;""".format(userId)
		enquiryQuery = """select enq._id,enq.enquiryBy,enq.toConsigneeId,enq.pickupAddresssId,enq.weight,enq.truckType,enq.material,enq.unloadingExpense,enq.loadingExpense,enq.loadingTime,enq.advance,enq.againstBill,enq.remarks,enq.timestamp,enq.enquirystatus,fleetosdb.shipments.tracking_status,fleetosdb.shipments.delivered,fleetosdb.bids.status,count(enq._id) as no from fleetosdb.enquiries as enq left join fleetosdb.shipments on shipments.enquiryId=enq._id left join fleetosdb.bids on fleetosdb.bids.enquiryId=enq._id where enq.enquiryBy={} and enq.enquirystatus=0 group by enq._id  order by enq._id desc;""".format(userId)
		df = pd.read_sql(enquiryQuery, engine)
		# print(df)
		

		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			enquiriesList = json.loads(data)
			
			toEnq = []
			fromEnq = []
			for item in enquiriesList:
				
				consigneeQuery = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state).filter(ConsigneeMasterData.userId == item['toConsigneeId']).statement
				df1 = pd.read_sql(consigneeQuery, engine)
				toDetails = df1.to_json(orient="records")
				toDetails = json.loads(toDetails)
				toEnq.append(toDetails[0])
				# result['enquiriesList']['to'].append(toDetails)
				

				consigneeQuery = session.query(ConsignorAddress).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state).filter(ConsignorAddress._id == item['pickupAddresssId']).statement
				df2 = pd.read_sql(consigneeQuery, engine)
				fromDetails = df2.to_json(orient="records")
				fromDetails = json.loads(fromDetails)
				fromEnq.append(fromDetails[0])

			# result['to'] = toEnq
			# result['from'] = fromEnq
			return jsonify(enquiriesList=enquiriesList,toEnq=toEnq,fromEnq=fromEnq)

	# except exc.SQLAlchemyError as err:
	# 	error = str(err.__dict__['orig'])
	# 	print("error:"+error)
	except Exception as e:
		print(e)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)

#get short enquiry data
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbEnquiryDataById(enquiryId, current_identity,session=None):
	try:
		enquiryQuery = session.query(Enquiry).filter(Enquiry._id == enquiryId).statement
		df = pd.read_sql(enquiryQuery, engine)
		bidQuery = session.query(Bids).filter(Bids.transporterId == current_identity,Bids.enquiryId==enquiryId).statement
		bid_df = pd.read_sql(bidQuery, engine)
		databid = bid_df.to_json(orient="records")
		bid_info = json.loads(databid)
		print("bid_info",bid_info)
		ranking = """select ranking_data.sn from (SELECT row_number() over(order by(fleetosdb.bids.advance+fleetosdb.bids.againstBill)) as sn,fleetosdb.bids.transporterId FROM fleetosdb.enquiries  inner join fleetosdb.bids on fleetosdb.enquiries._id=fleetosdb.bids.enquiryId where fleetosdb.enquiries._id={}) as ranking_data where transporterId={}""".format(enquiryId, current_identity)
		#ranking="""select ranking_data.sn from (SELECT row_number() over(order by(tran.bids.advance+tran.bids.againstBill)) as sn,tran.bids.transporterId FROM tran.enquiries  inner join tran.bids on tran.enquiries._id=tran.bids.enquiryId where tran.enquiries._id={}) as ranking_data where transporterId={}""".format(enquiryId,current_identity)
		rank_df = pd.read_sql(ranking, engine)
		bid_rank = rank_df.to_dict(orient="records")
		

		print("databid:",databid)
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			enquiry= json.loads(data)

			consigneeQuery = session.query(ConsigneeMasterData,Users).with_entities(Users.firebaseUid,ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.companyName).filter(and_(ConsigneeMasterData.userId == enquiry[0]['toConsigneeId'],Users.userId == enquiry[0]['toConsigneeId'])).statement
			df1 = pd.read_sql(consigneeQuery, engine)
			toDetails = []
			fromDetails = []

			if(not df1.empty):
				toDetails = df1.to_json(orient="records")
				data = json.loads(toDetails)
				toDetails = data[0]
			
			consigneeQuery = session.query(ConsignorAddress,ConsignorMasterData,Users).with_entities(Users.firebaseUid,ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state,ConsignorMasterData.companyName).filter(and_(ConsignorAddress._id == enquiry[0]['pickupAddresssId']),(ConsignorMasterData.userId == ConsignorAddress.consignorId),(Users.userId == ConsignorMasterData.userId)).statement
			df2 = pd.read_sql(consigneeQuery, engine)
			if(not df2.empty):
				fromDetails = df2.to_json(orient="records")
				fromDetails = json.loads(fromDetails)
				fromDetails = fromDetails[0]
			if bid_df.empty and rank_df.empty:
				return jsonify(enquiry=enquiry[0], toAddress=toDetails, fromAddress=fromDetails)
			else:
				return jsonify(enquiry=enquiry[0], toAddress=toDetails, fromAddress=fromDetails, databid=bid_info[0], bid_rank=bid_rank[0])
	except Exception as e:
		print(e)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbTransporterEnquiryData(userId,session=None):
	try:
		enquiryQuery = session.query(TransporterMasterData).filter(TransporterMasterData.userId == userId).statement
		df = pd.read_sql(enquiryQuery, engine)
		
		data = df.to_json(orient="records")
		

		if(df.empty):
			return None
		else:
			enquiry = json.loads(data)
			# print(df)
			print(df['_id'][0])
			
			result = {}
			result['transporter'] = enquiry

			transQuery = session.query(SelectedTransporter).with_entities(SelectedTransporter.enquiryId).filter(
				SelectedTransporter.selectedTransporterId == df['_id'][0]).order_by(SelectedTransporter.enquiryId.desc()).statement
			df = pd.read_sql(transQuery, engine)
			
			data = df.to_json(orient="records")
			selectedTransporter = json.loads(data)
			print(selectedTransporter)

			enqInfo = []
			dropLocationInfo = []
			for item in selectedTransporter:
				print(item['enquiryId'])
				enqQuery = session.query(Enquiry).with_entities(Enquiry.loadingTime, Enquiry.toConsigneeId, Enquiry._id, Enquiry.advance, Enquiry.againstBill, Enquiry.loadingExpense,
                                                    Enquiry.material, Enquiry.unloadingExpense, Enquiry.weight, Enquiry.remarks).filter(Enquiry._id == item['enquiryId']).statement
				df = pd.read_sql(enqQuery, engine)
				data = df.to_json(orient="records")
				enqInfor = json.loads(data)
				print(enqInfor)
				enqInfo.append(enqInfor[0])
				
				consigQuery = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.userName,ConsigneeMasterData.companyName).filter(ConsigneeMasterData.userId == enqInfor[0]['toConsigneeId']).statement
				df = pd.read_sql(consigQuery, engine)
				data = df.to_json(orient="records")
				consigneeInfo = json.loads(data)
				dropLocationInfo.append(consigneeInfo[0])

			result['enqInfo'] = enqInfo
			result['dropLocationInfo'] = dropLocationInfo
			return result

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbTransporterAllEnquiryData(userId,session=None):
	try:
		enquiryQuery = session.query(TransporterMasterData).filter(TransporterMasterData.userId == userId).statement
		df = pd.read_sql(enquiryQuery, engine)
		
		data = df.to_json(orient="records")
		

		if(df.empty):
			return None
		else:
			enquiry = json.loads(data)
			# print(df)
			print(df['_id'][0])
			
			result = {}
			result['transporter'] = enquiry

			transQuery = session.query(SelectedTransporter).with_entities(SelectedTransporter.enquiryId).filter(
				SelectedTransporter.selectedTransporterId == df['_id'][0]).order_by(SelectedTransporter.enquiryId.desc()).statement
			df = pd.read_sql(transQuery, engine)
			
			data = df.to_json(orient="records")
			selectedTransporter = json.loads(data)
			# print(selectedTransporter)

			enqInfo = []
			dropLocationInfo = []
			pickupLocationInfo = []
			for item in selectedTransporter:
				print(item['enquiryId'])
				enqQuery = session.query(Enquiry).with_entities(Enquiry._id,Enquiry.loadingTime,Enquiry.toConsigneeId,Enquiry.pickupAddresssId,Enquiry.advance,Enquiry.againstBill,Enquiry.loadingExpense,Enquiry.material,Enquiry.unloadingExpense,Enquiry.weight,Enquiry.remarks).filter(Enquiry._id == item['enquiryId']).order_by(Enquiry.timestamp.desc()).statement
				df = pd.read_sql(enqQuery, engine)
				data = df.to_json(orient="records")
				enqInfor = json.loads(data)
				enqInfo.append(enqInfor[0])
				
				consigQuery = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.userName,ConsigneeMasterData.companyName).filter(ConsigneeMasterData.userId == enqInfor[0]['toConsigneeId']).statement
				df = pd.read_sql(consigQuery, engine)
				data = df.to_json(orient="records")
				consigneeInfo = json.loads(data)
				dropLocationInfo.append(consigneeInfo[0])

				fromConsigQuery = session.query(ConsignorAddress,ConsignorMasterData).with_entities(ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state,ConsignorAddress.pincode,ConsignorMasterData.companyName).filter(and_(ConsignorAddress._id == enqInfor[0]['pickupAddresssId']),(ConsignorMasterData.userId == ConsignorAddress.consignorId)).statement
				df = pd.read_sql(fromConsigQuery, engine)
				data = df.to_json(orient="records")
				pickupLocationInfor = json.loads(data)
				pickupLocationInfo.append(pickupLocationInfor[0])

			result['enqInfo'] = enqInfo
			result['dropLocationInfo'] = dropLocationInfo
			result['pickupLocationInfo'] = pickupLocationInfo
			return result

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbTransporterEnquiryDataById(userId,enquiryId,session=None):
	try:
		enquiryQuery = session.query(Enquiry).filter(Enquiry._id == enquiryId).statement
		df = pd.read_sql(enquiryQuery, engine)
		# print(df)
		
		

		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			enq = json.loads(data)
			result = {}
			result['enquiry'] = enq

			toEnq = []
			fromEnq = []
			for item in enq:
				
				consigneeQuery = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.companyName).filter(ConsigneeMasterData.userId == item['toConsigneeId']).statement
				df1 = pd.read_sql(consigneeQuery, engine)
				toDetails = df1.to_json(orient="records")
				toDetails = json.loads(toDetails) 
				toEnq.append(toDetails)

				consigneeQuery = session.query(ConsignorAddress,ConsignorMasterData).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state,ConsignorMasterData.companyName).filter(and_(ConsignorAddress._id == item['pickupAddresssId']),(ConsignorMasterData.userId == ConsignorAddress.consignorId)).statement
				df2 = pd.read_sql(consigneeQuery, engine)
				fromDetails = df2.to_json(orient="records")
				fromDetails = json.loads(fromDetails)
				fromEnq.append(fromDetails)

			result['to'] = toEnq
			result['from'] = fromEnq
			return result

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbCheckUser(userId,session=None):
	try:
		checkQuery = session.query(Users).filter(Users.userId == userId).statement
		df = pd.read_sql(checkQuery, engine)

		if(df.empty):
			return None
		else:
			return df.to_json(orient="records")

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbCheckUserByEmail(email,session=None):
	try:
		checkQuery = session.query(Users).filter(Users.email == email).statement
		df = pd.read_sql(checkQuery, engine)

		if(df.empty):
			return None
		else:
			return df.to_json(orient="records")

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbChangePassword(userId,newPassword,session=None):
	try:
		data = {'password':newPassword}
		session.query(Users).filter(Users.userId  == userId).update(data)
		session.commit()
		return 'success'

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)


@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbChangeEnquiryStatus(current_identity, enquiry_id, session=None):
	try:
		data={"enquirystatus":1}
		session.query(Enquiry).filter(Enquiry.enquiryBy == current_identity,Enquiry._id == enquiry_id).update(data)
		session.commit()
		return 'success'

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)


@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbregisterfcmtoken(current_identity,token, session=None):
	try:
		data = {"fcmtoken": token}
		session.query(Users).filter(Users.userId ==current_identity).update(data)
		session.commit()
		return 'success'

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

#get short enquiry data
# @retry_db((OperationalError, StatementError), n_retries=30)
# @mk_session
# def dbEnquiryDataById(enquiryId,session=None):
# 	try:
# 		enquiryQuery = session.query(Enquiry).filter(Enquiry._id == enquiryId).statement
# 		df = pd.read_sql(enquiryQuery, engine)
# 		# print(df)
# 		data = df.to_json(orient="records")
# 		enq = json.loads(data)
# 		result = {}
# 		result['enquiry'] = enq
# 		if(df.empty):
# 			return None
# 		else:
# 			toEnq = []
# 			fromEnq = []
# 			for item in enq:
				
# 				consigneeQuery = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state).filter(ConsigneeMasterData.userId == item['toConsigneeId']).statement
# 				df1 = pd.read_sql(consigneeQuery, engine)
# 				toDetails = df1.to_json(orient="records")
# 				toDetails = json.loads(toDetails)
# 				toEnq.append(toDetails)

# 				consigneeQuery = session.query(ConsignorAddress).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state).filter(ConsignorAddress._id == item['pickupAddresssId']).statement
# 				df2 = pd.read_sql(consigneeQuery, engine)
# 				fromDetails = df2.to_json(orient="records")
# 				fromDetails = json.loads(fromDetails)
# 				fromEnq.append(fromDetails)

# 			result['to'] = toEnq
# 			result['from'] = fromEnq
# 			return result

# 	except exc.SQLAlchemyError as err:
# 		error = str(err.__dict__['orig'])
# 		print("error:"+error)
