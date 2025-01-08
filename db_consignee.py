from os import stat
import re
from sqlalchemy.sql.functions import user
import models
import pandas as pd
from flask import json, jsonify
from sqlalchemy import exc
from models import *
import sys

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
def dbConsigneeAccount(userId,session=None):
     try:

          q1 = session.query(ConsigneeMasterData,Users).with_entities(ConsigneeMasterData,Users.firebaseUid).filter(and_(ConsigneeMasterData.userId == userId,Users.userId == userId)).statement
          df = pd.read_sql(q1, engine)
          
          if(df.empty):
               return jsonify(success=False,msg='Consignee profile not found!')
          else:
               data = df.to_json(orient="records")
               data = json.loads(data)
          
               return jsonify(success=True,result=data[0])

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)
 
@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbEnquiryDataForConsignee(userId,session=None):
	try:
		
		enquiryQuery = session.query(Enquiry).filter(Enquiry.toConsigneeId == userId).order_by(Enquiry.timestamp.desc()).statement
		df = pd.read_sql(enquiryQuery, engine)

		
		# return enquiries

		if(df.empty):
			return jsonify(success=False,msg='No enquiry found!')
		else:
			data = df.to_json(orient="records")
			enquiries = json.loads(data)

			consignorAddressList = []
			
			consigneeQuery = session.query(ConsigneeMasterData).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state).filter(ConsigneeMasterData.userId == userId).statement
			df1 = pd.read_sql(consigneeQuery, engine)
			toDetails = df1.to_json(orient="records")
			consigneeLocation = json.loads(toDetails)

			for item in enquiries:
				
				consigneeQuery = session.query(ConsignorAddress).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state).filter(ConsignorAddress._id == item['pickupAddresssId']).statement
				df2 = pd.read_sql(consigneeQuery, engine)
				fromDetails = df2.to_json(orient="records")
				fromDetails = json.loads(fromDetails)
				consignorAddressList.append(fromDetails[0])

			return jsonify(enquiries=enquiries,consigneeLocation=consigneeLocation[0],consignorAddressList=consignorAddressList)

	except Exception as e:
		print(e)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def dbShipmentDataForConsignee(userId,session=None):
	try:
		q = session.query(Shipments, Bids, Enquiry, ConsigneeMasterData, ConsignorAddress, TransporterMasterData).filter(and_(Shipments.bidId == Bids._id, Shipments.enquiryId == Enquiry._id, Enquiry.toConsigneeId == userId, ConsigneeMasterData.userId == userId, ConsignorAddress._id == Enquiry.pickupAddresssId, TransporterMasterData.userId == Shipments.transporterId)).with_entities(Shipments, Bids, ConsigneeMasterData.location.label('toLocation'), ConsigneeMasterData.address.label('toAddress'), ConsigneeMasterData.district.label('toDistrict'), ConsigneeMasterData.state.label('toState'), ConsignorAddress.location.label('fromLocation'), ConsignorAddress.address.label('fromAddress'), ConsignorAddress.district.label('fromDistrict'), ConsignorAddress.state.label('fromState'), TransporterMasterData.userName.label('transporterName')).order_by(Shipments.timestamp.desc()).statement
		df = pd.read_sql(q, engine)

		
		if(df.empty):
			return jsonify(success=False,msg='No shipment found!')
		else:
			data = df.to_json(orient="records")
			shipments = json.loads(data)
			return shipments

	except Exception as e:
		print(e)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsigneeProfileDetails(userId,session:None):
     try:
          q = session.query(ConsigneeMasterData).filter(ConsigneeMasterData.userId == userId).with_entities(ConsigneeMasterData.companyName,ConsigneeMasterData.address,ConsigneeMasterData.userName,ConsigneeMasterData.truckCount,ConsigneeMasterData.panNumber,ConsigneeMasterData.gstNumber).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return None
          else:
               data = df.to_json(orient="records")
               data = json.loads(data)

               return data

     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbConsigneeProfileUpdate(userId,companyName,userName,address,panNumber,gstNumber,session:None):
     try:
          q = session.query(ConsigneeMasterData).filter(ConsigneeMasterData.userId == userId).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return None
          else:
               
               data = {'companyName':companyName,'userName':userName,'address':address,'panNumber':panNumber,'gstNumber':gstNumber}
               update = session.query(ConsigneeMasterData).filter(ConsigneeMasterData.userId  == userId).update(data)
               session.commit()
               return 'success'


     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)