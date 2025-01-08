from os import stat
import re
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
import sys
from firebase_admin import auth

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

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsignorAddressAdd(userId,addressDict,session=None):
	try:
		
		# query=session.query(ConsignorAddress).filter(and_(ConsignorAddress.consignorId==userId),(ConsignorAddress.isDefault==True)).statement
		q = session.query(ConsignorAddress).filter(and_(ConsignorAddress.consignorId == userId),(ConsignorAddress.isDefault==1)).statement
		df = pd.read_sql(q, engine)
		# print(df)
		
		
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			adrs = json.loads(data)

			flag = 0
			for item  in addressDict:
				# print(int(item['isDefault']))
				if int(item['isDefault']) == 1:
					flag = 1
			
			if(flag):
				# print(flag)
				data = {'isDefault': 0}
				updateLiveAssets = session.query(ConsignorAddress).filter(and_(ConsignorAddress.consignorId == userId),(ConsignorAddress.isDefault == 1)).update(data)
				session.commit()
			
			for item  in addressDict:
				insertAddresses = ConsignorAddress(address = item['address'], location=item['location'],district=item['district'], state=item['state'], pincode=item['pincode'], consignorId=userId,isDefault=int(item['isDefault']), timestamp = datetime.now())
				session.add(insertAddresses)
				session.commit()
		return('success')
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsignorAddressUpdate(userId,addressDict,session=None):
	try:
		q = session.query(ConsignorAddress).filter(and_(ConsignorAddress.consignorId == userId),(ConsignorAddress.isDefault==1)).statement
		df = pd.read_sql(q, engine)
		# print(df)
		data = df.to_json(orient="records")
		
		if(not df.empty):
			session.query(ConsignorAddress).filter(ConsignorAddress.consignorId == userId).delete()
			session.commit()
			
		for item  in addressDict:
			insertAddresses = ConsignorAddress(address = item['address'], location=item['location'],district=item['district'], state=item['state'], pincode=item['pincode'], consignorId=userId,isDefault=int(item['isDefault']), timestamp = datetime.now())
			session.add(insertAddresses)
			session.commit()

		return('success')

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsignorAddressData(userId,session=None):
	try:
		
		# query=session.query(ConsignorAddress).filter(and_(ConsignorAddress.consignorId==userId),(ConsignorAddress.isDefault==True)).statement
		q = session.query(ConsignorAddress).filter(ConsignorAddress.consignorId == userId).statement
		df = pd.read_sql(q, engine)
		# print(df)
		
		
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			adrs = json.loads(data)
			return(adrs)
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)


@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsignorAcount(userId,session=None):
	try:
		q = session.query(ConsignorMasterData,Users).with_entities(ConsignorMasterData,Users.firebaseUid).filter(and_(ConsignorMasterData.userId == userId),(Users.userId == userId)).statement
		df = pd.read_sql(q, engine)
		# print(df)
		
		
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			adrs = json.loads(data)
			return(adrs)
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbCompanyList(session=None):
	try:
		q = session.query(ConsignorMasterData).with_entities(ConsignorMasterData.companyName).statement
		df = pd.read_sql(q, engine)
		# print(df)
		
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			adrs = json.loads(data)
			return(adrs)
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbConsignorAcountDetails(userId,session=None):
	try:
		q = session.query(ConsignorMasterData).filter(ConsignorMasterData.userId == userId).statement
		df = pd.read_sql(q, engine)
		# print(df)
		result = {}
		
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			data = json.loads(data)
			result['data'] = data

			q = session.query(ConsignorAddress).filter(ConsignorAddress.consignorId == userId).statement
			df = pd.read_sql(q, engine)
			data = df.to_json(orient="records")
			data = json.loads(data)
			result['address'] = data

			return(result)
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbConsigneeList(userId,session=None):
	try:
		q = session.query(ConsigneeMasterData,Users).with_entities(Users.email,Users.role,ConsigneeMasterData._id,ConsigneeMasterData.userName,ConsigneeMasterData.companyName,ConsigneeMasterData.adminName,ConsigneeMasterData.contact,ConsigneeMasterData.address,ConsigneeMasterData.pincode,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.gstNumber,ConsigneeMasterData.panNumber,ConsigneeMasterData.addByConsignor).filter(and_(ConsigneeMasterData.consignorId == userId),(ConsigneeMasterData.userId == Users.userId)).statement
		df = pd.read_sql(q, engine)
		# print(df)
		result = {}
		
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			data = json.loads(data)
			result['consignees'] = data

			return(result)
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)


@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbConsignorList(session=None):
	try:
		q = session.query(ConsignorMasterData,Users).with_entities(ConsignorMasterData._id,ConsignorMasterData.userId,ConsignorMasterData.userName,ConsignorMasterData.companyName,ConsignorMasterData.email).statement
		df = pd.read_sql(q, engine)
		# print(df)
		result = {}
		
		if(df.empty):
			return None
		else:
			data = df.to_json(orient="records")
			data = json.loads(data)
			result['consignors'] = data

			return(result)
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbConsigneeUpdate(current_identity,consignee_master_id,contact,userName,companyName,adminName,managerName,address,pincode,location,panNumber,gstNumber,district,state,session=None):
	try:
		print(current_identity)
		print(current_identity)
		checkUser = session.query(ConsigneeMasterData).filter(and_(ConsigneeMasterData._id == consignee_master_id,ConsigneeMasterData.consignorId == current_identity)).statement
		df = pd.read_sql(checkUser, engine)
		if(df.empty):
			return ({'success':False,'message':'This consignee is not added by you!'}),400

		addByConsignor = df['addByConsignor'].tolist()
		if(addByConsignor[0] == 1):
			data = {'userName': userName,'contact':contact,'companyName':companyName,'adminName':adminName,'managerName':managerName,'address':address,'pincode':pincode,'location':location,'panNumber':panNumber,'gstNumber':gstNumber,'state':state,'district':district}
			df = session.query(ConsigneeMasterData).filter(and_(ConsigneeMasterData._id == consignee_master_id),(ConsigneeMasterData.consignorId == current_identity)).update(data)
			session.commit()
			
			if(df>0):
				return ({'success':True,'message':'Consignee profile updated!'})
			else:
				return ({'success':False,'message':'Failed to update!'}),400
		else:
			return ({'success':False,'message':'This consignee is not added by you!'}),400
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError), n_retries=30)
@mk_session
def dbDeleteConsignee(current_identity,consigneeMasterId,session=None):
	try:
		q = session.query(ConsigneeMasterData).filter(ConsigneeMasterData._id == consigneeMasterId).statement
		df = pd.read_sql(q, engine)
		data = df.to_json(orient="records")
		data = json.loads(data)
		# print(data[0]['email'])
		user = auth.get_user_by_email(data[0]['email'])
		auth.delete_user(user.uid)

		df1 = session.query(UserTokens).filter(UserTokens._userId == data[0]['userId']).delete()
		session.commit()

		df2 = session.query(ConsigneeMasterData).filter(and_(ConsigneeMasterData._id == consigneeMasterId),(ConsigneeMasterData.consignorId == current_identity)).delete()
		session.commit()

		df1 = session.query(Users).filter(Users.userId == data[0]['userId']).delete()
		session.commit()

		output={}
		
		output['success'] = True
		output['msg'] = 'Consignee removed!'
		return jsonify(output)
		
		
	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsignorProfileDetails(userId,session:None):
     try:
          q = session.query(ConsignorMasterData).filter(ConsignorMasterData.userId == userId).with_entities(ConsignorMasterData.companyName,ConsignorMasterData.address,ConsignorMasterData.userName,ConsignorMasterData.truckCount,ConsignorMasterData.panNumber,ConsignorMasterData.gstNumber).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return None
          else:
               data = df.to_json(orient="records")
               data = json.loads(data)

               q = session.query(ConsignorAddress).filter(ConsignorAddress.userId == userId).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state,ConsignorAddress.pincode).statement
               df = pd.read_sql(q, engine)
               addresses = df.to_json(orient="records")
               addresses = json.loads(addresses)
               
               return jsonify(profile=data ,addresses=addresses)

     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsignorProfileUpdate(userId,companyName,userName,panNumber,gstNumber,address,location,district,state,pincode,session:None):
     try:
          q = session.query(ConsignorMasterData).filter(ConsignorMasterData.userId == userId).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return None
          else:
               
               data = {'companyName':companyName,'userName':userName,'panNumber':panNumber,'gstNumber':gstNumber}

               update = session.query(ConsignorMasterData).filter(ConsignorMasterData.userId  == userId).update(data)
               session.commit()
			
               update = session.query(ConsignorAddress).filter(ConsignorAddress.consignorId  == userId).update({'address':address,'location':location,'district':district,'state':state,'pincode':pincode})
               session.commit()

               return 'success'


     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)
	  
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def  dbsupervisorList(userId, session=None):
	try:
		supervisor_list = session.query(Users, SupervisorMasterData, ConsignorMasterData).with_entities(SupervisorMasterData._id, SupervisorMasterData.userId.label("SupervisorUserId"), SupervisorMasterData.consignorId.label("consignerUserId"), Users.userId, Users.email, Users.role, SupervisorMasterData.userName, SupervisorMasterData.contact).filter(
			SupervisorMasterData.consignorId == ConsignorMasterData._id, Users.userId == SupervisorMasterData.userId, ConsignorMasterData.userId == userId).statement
		df_list = pd.read_sql(supervisor_list, engine)
		if(df_list.empty):
			return None
		else:
			print("check data.......")
			data=df_list.to_json(orient="records")
			data = json.loads(data)
			return data

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)


@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def updateSupervisor(supervisor_id, supervisorUserId, email, userName, contact, session=None):
	try:
		data1 = {'email': email}
		data2 = {'userName': userName,'contact': contact}
		supervisor=session.query(SupervisorMasterData).filter(SupervisorMasterData._id == supervisor_id, SupervisorMasterData.userId == supervisorUserId).update(data2)
		session.commit()
		user=session.query(Users).filter(Users.userId == supervisorUserId).update(data1)
		session.commit()
		if supervisor==1 and user==1:
			return "success"
		else:
			return "please provide correct supervisor_id and supervisorUserId"

	except exc.SQLAlchemyError as err:
		error = str(err.__dict__['orig'])
		print("error:"+error)
