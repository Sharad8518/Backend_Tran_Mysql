from os import stat
import re

from sqlalchemy.sql.functions import user
import models
import pandas as pd
from flask import json, jsonify
from sqlalchemy import exc
from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.sql.sqltypes import DateTime, NullType, String
from models import *
from passlib.hash import sha256_crypt
from datetime import datetime, timedelta
import secrets
import sys
from datetime import date
import os

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
def dbShipmentUpdate(userId,status,remark,shipmentId,session=None):
     try:
          q = session.query(Shipments).filter(Shipments._id == shipmentId).statement
          df = pd.read_sql(q, engine)
		# print(df)
          
          if(df.empty):
               return None
          else:
               data = {'tracking_status' : status,'tracking_remark':remark,'tracking_postedby':userId}
               update = session.query(Shipments).filter(Shipments._id  == shipmentId).update(data)
               session.commit()
               if status=="Delivered":
                    # message = Mail(from_email='from_email@example.com',
                    # to_emails='to@example.com',
                    # subject='Sending with Twilio SendGrid is Fun',
                    # html_content='<strong>and easy to do anywhere, even with Python</strong>')
                    get_consignee_data = session.query(Shipments, Enquiry, Users, ConsignorMasterData).with_entities(Users.email, Enquiry.material, Enquiry.weight, Enquiry.truckType, ConsignorMasterData.userName, ConsignorMasterData.companyName).filter(
                       Enquiry._id == Shipments.enquiryId, ConsignorMasterData.userId == Shipments.requesterId, Users.userId == Enquiry.toConsigneeId, Shipments._id == shipmentId).statement
                    df = pd.read_sql(get_consignee_data, engine)
                    email_data = df.to_json(orient="records")
                    data = json.loads(email_data)
                    print("Update Notification data:", data)
                    return 1, data
               return 1, "Not Delivered"

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbShipmentComplete(userId,remark,shipmentId,session=None):
     try:
          q = session.query(Shipments).filter(Shipments._id == shipmentId).statement
          df = pd.read_sql(q, engine)
		
          if(df.empty):
               return None
          else:
               data = {'tracking_status':'Delivered','tracking_remark':remark,'tracking_postedby':userId,'delivered':date.today()}
               update = session.query(Shipments).filter(Shipments._id  == shipmentId).update(data)
               session.commit()
               get_consignee_data = session.query(Shipments, Enquiry, Users, ConsignorMasterData).with_entities(Users.email, Enquiry.material, Enquiry.weight, Enquiry.truckType, ConsignorMasterData.userName, ConsignorMasterData.companyName).filter(
                  Enquiry._id == Shipments.enquiryId, ConsignorMasterData.userId == Shipments.requesterId, Users.userId == Enquiry.toConsigneeId, Shipments._id == shipmentId).statement
               df = pd.read_sql(get_consignee_data, engine)
               email_data = df.to_json(orient="records")
               data = json.loads(email_data)
               print("slist:",data)
               return 1,data

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbShipmentData(shipmentId,session=None):
     try:
          result = {}
          q = session.query(Shipments).filter(Shipments._id == shipmentId).statement
          df = pd.read_sql(q, engine)
		# print(df)
          enquiryId = df['enquiryId'].tolist()
          transporterId = df['transporterId'].tolist()
          requesterId = df['requesterId'].tolist()
          bidId = df['bidId'].tolist()

          if(df.empty):
               return None
          else:
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['shipment'] = data
               q = session.query(Enquiry).filter(Enquiry._id == enquiryId[0]).statement
               df = pd.read_sql(q, engine)
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['enquiry'] = data
 
               pickupAddresssId = df['pickupAddresssId'].tolist()
               toConsigneeId = df['toConsigneeId'].tolist()

               q = session.query(TransporterMasterData,Users).filter(and_(TransporterMasterData.userId == transporterId[0],Users.userId == transporterId[0])).with_entities(Users.firebaseUid,TransporterMasterData.address,TransporterMasterData.companyName,TransporterMasterData.contact,TransporterMasterData.email,TransporterMasterData.location,TransporterMasterData.gstNumber,TransporterMasterData.panNumber,TransporterMasterData.truckCount,TransporterMasterData.pincode).statement
               df = pd.read_sql(q, engine)
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['transporter'] = data

               q = session.query(ConsignorMasterData,Users).filter(and_(ConsignorMasterData.userId == requesterId[0],Users.userId == requesterId[0])).with_entities(ConsignorMasterData.companyName,ConsignorMasterData.userName,ConsignorMasterData.panNumber,ConsignorMasterData.gstNumber,ConsignorMasterData.email,ConsignorMasterData.contact,Users.firebaseUid).statement
               df = pd.read_sql(q, engine)
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['requester'] = data

               q = session.query(ConsignorAddress).filter(ConsignorAddress._id == pickupAddresssId[0]).with_entities(ConsignorAddress.address,ConsignorAddress.district,ConsignorAddress.state).statement
               df = pd.read_sql(q, engine)
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['fromAddress'] = data

               q = session.query(ConsigneeMasterData,Users).filter(and_(ConsigneeMasterData.userId == toConsigneeId[0],Users.userId == toConsigneeId[0])).with_entities(Users.firebaseUid,ConsigneeMasterData.address,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.pincode,ConsigneeMasterData.contact,ConsigneeMasterData.userName).statement
               df = pd.read_sql(q, engine)
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['toAddress'] = data

               q=session.query(Bids).filter(Bids._id==bidId).statement
               df = pd.read_sql(q, engine)
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['Bids'] = data
          return result

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbShipmentforConsignor(userId,session=None):
     try:

          result = {}
          
          q = session.query(Shipments).filter(Shipments.requesterId == userId).order_by(Shipments.timestamp.desc()).statement
          df = pd.read_sql(q, engine)
          slist = df.to_json(orient="records")
          slist = json.loads(slist)
          

          if(len(slist)>0):
               result['transporter']=[]
               result['shipment'] = []
               result['enquiry'] = []
               result['fromAddress'] = []
               result['toAddress'] = []

               for s in slist:

                    result['shipment'].append(s)
                    print(s['transporterId'])
                    q = session.query(TransporterMasterData).filter(TransporterMasterData.userId == s['transporterId']).with_entities(TransporterMasterData.userName,TransporterMasterData.contact,TransporterMasterData.location,TransporterMasterData.address,TransporterMasterData.truckCount).statement
                    df = pd.read_sql(q, engine)
                    data = df.to_json(orient="records")
                    data = json.loads(data)
                    print(data)

                    result['transporter'].append(data[0])

                    q = session.query(Enquiry).filter(Enquiry._id == s['enquiryId']).with_entities(Enquiry.weight,Enquiry.advance,Enquiry.againstBill,Enquiry.loadingExpense,Enquiry.loadingTime,Enquiry.material,Enquiry.pickupAddresssId,Enquiry.toConsigneeId).statement
                    df = pd.read_sql(q, engine)
                    enq = df.to_json(orient="records")
                    enq = json.loads(enq)
                    result['enquiry'].append(enq[0])

                    pickupAddresssId = df['pickupAddresssId'].tolist()
                    toConsigneeId = df['toConsigneeId'].tolist()

                    q = session.query(ConsigneeMasterData).filter(ConsigneeMasterData.userId == toConsigneeId[0]).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.district,ConsigneeMasterData.state).statement
                    df = pd.read_sql(q, engine)
                    consigneedata = df.to_json(orient="records")
                    consigneedata = json.loads(consigneedata)
                    result['toAddress'].append(consigneedata[0])
               
                    q = session.query(ConsignorAddress).filter(ConsignorAddress._id == pickupAddresssId[0]).with_entities(ConsignorAddress.address,ConsignorAddress.district,ConsignorAddress.state).statement
                    df = pd.read_sql(q, engine)
                    data = df.to_json(orient="records")
                    data = json.loads(data)
                    result['fromAddress'].append(data[0])

               return result
          else:
               return jsonify(success=False,msg='No shipment data found!')

     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbShipmentforTransporter(userId,session=None):
     try:
          result = {}
          q = session.query(Shipments).filter(Shipments.transporterId == userId).order_by(Shipments.timestamp.desc()).statement
          df = pd.read_sql(q, engine)
          slist = df.to_json(orient="records")
          slist = json.loads(slist)

          if(df.empty):
               return None
          else:
               result = {}

               if(len(slist)>0):
                    result['shipment'] = []
                    result['enquiry'] = []
                    result['fromAddress'] = []
                    result['toAddress'] = []

                    

                    for s in slist:

                         result['shipment'].append(s)

                         enquiryId = s['enquiryId']
                         # print(enquiryId)
                         q = session.query(Enquiry).filter(Enquiry._id == enquiryId).statement
                         df = pd.read_sql(q, engine)
                         enq = df.to_json(orient="records")
                         enq = json.loads(enq)

                         result['enquiry'].append(enq[0])

                         pickupAddresssId = df['pickupAddresssId'].tolist()
                         toConsigneeId = df['toConsigneeId'].tolist()

                         q = session.query(ConsigneeMasterData).filter(ConsigneeMasterData.userId == toConsigneeId[0]).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.district,ConsigneeMasterData.state).statement
                         df = pd.read_sql(q, engine)
                         consigneedata = df.to_json(orient="records")
                         consigneedata = json.loads(consigneedata)
                         result['toAddress'].append(consigneedata[0])
                    
                         q = session.query(ConsignorAddress).filter(ConsignorAddress._id == pickupAddresssId[0]).with_entities(ConsignorAddress.address,ConsignorAddress.district,ConsignorAddress.state).statement
                         df = pd.read_sql(q, engine)
                         data = df.to_json(orient="records")
                         data = json.loads(data)
                         result['fromAddress'].append(data[0])

               return result

     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)