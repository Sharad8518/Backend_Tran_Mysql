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
from datetime import date, datetime, timedelta
import secrets
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
def dbTransporterBidsList(session=None):
     try:
          
          q = session.query(Bids).statement
          df = pd.read_sql(q, engine)
		# print(df)
          
          if(df.empty):
               return None
          else:
               result = {}
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['list'] = data

               if(len(data)>0):
                    
                    res = []
                    for u in data:
                         trans = session.query(TransporterMasterData).filter(TransporterMasterData.userId == u['transporterId']).with_entities(TransporterMasterData.companyName).statement
                         df = pd.read_sql(trans, engine)
                         enqData = df.to_json(orient="records")
                         enqData = json.loads(enqData)
                         result['companyName'] = enqData

                         enq = session.query(Enquiry).filter(Enquiry._id == u['enquiryId']).with_entities(Enquiry.weight,Enquiry.loadingTime).statement
                         df = pd.read_sql(enq, engine)
                         enqData = df.to_json(orient="records")
                         enqData = json.loads(enqData)
                         result['enquiry'] = enqData

                         consignorAdrs = session.query(ConsignorAddress,Enquiry).filter(and_(ConsignorAddress._id == Enquiry.pickupAddresssId),(Enquiry._id == u['enquiryId'])).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state,ConsignorAddress.pincode).statement
                         df = pd.read_sql(consignorAdrs, engine)
                         fromlocation = df.to_json(orient="records")
                         fromlocation = json.loads(fromlocation)
                         result['from']=fromlocation

                         consigneeAdrs = session.query(ConsigneeMasterData,Enquiry).filter(and_(ConsigneeMasterData.userId == Enquiry.toConsigneeId),(Enquiry._id == u['enquiryId'])).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.pincode).statement
                         df = pd.read_sql(consigneeAdrs, engine)
                         tolocation = df.to_json(orient="records")
                         tolocation = json.loads(tolocation)
                         result['to']=tolocation

                         res.append(result.copy())

               return jsonify(res)
               

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbPostbid(userId, enquiryId, advance, againstBill, pickup, estimatedDelivery, remarks, bid_rate_type, rate, loading_included,total_freight,credit_period_for_balance_payment,bidStatus, session=None):
     try:
          q = session.query(Bids).filter(Bids.transporterId == userId,Bids.enquiryId == enquiryId).statement
          df = pd.read_sql(q, engine)
          databid = df.to_json(orient="records")
          databid = json.loads(databid)
		# print(df)
          
          insertBids = Bids(transporterId=userId, enquiryId=enquiryId, advance=advance, againstBill=againstBill, pickup=pickup, estimatedDelivery=estimatedDelivery, remarks=remarks, bid_rate_type=bid_rate_type, rate=rate, loading_included=loading_included, status=bidStatus,total_freight=total_freight, credit_period_for_balance_payment=credit_period_for_balance_payment,timestamp=datetime.now())
          if(df.empty):
               session.add(insertBids)
               session.commit()
               if(insertBids._id):
                   return insertBids._id
               else:
                    return None
          else:
               if databid[0]["status"] != "accepted" or databid[0]["status"] != "rejected":
                    try:
                        data = {"advance": advance, "againstBill": againstBill, "pickup": pickup, "estimatedDelivery": estimatedDelivery, "remarks": remarks, "bid_rate_type": bid_rate_type, "rate": rate, "loading_included": loading_included, "total_freight": total_freight,"credit_period_for_balance_payment": credit_period_for_balance_payment}
                        session.query(Bids).filter(Bids.transporterId ==userId, Bids.enquiryId == enquiryId,Bids.status=="pending").update(data)
                        session.commit()
                        return "Data saved"
                    except exc.SQLAlchemyError as err:
                         error = str(err.__dict__['orig'])
                         print("error:"+error)
               else:
                    return "Bid already accepted"
               


     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)


@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTransporterBidsByEnqId(enquiryId,session=None):
     try:
          q = session.query(Bids,Users,TransporterMasterData).filter(Bids.enquiryId == enquiryId,Users.userId==Bids.transporterId,TransporterMasterData.userId==Users.userId).order_by(Bids.advance+Bids.againstBill).statement
          df = pd.read_sql(q, engine)
		# print(df)
          result = {}
          if(df.empty):
              #transporter_not_bid = """select tran.transporter_masterdata.companyName,tran.users.firebaseUid,tran.consignor_address.location as consignor_location,tran.consignee_masterdata.location as consignee_location,tran.enquiries.loadingTime as pickuptime,tran.users.fcmtoken,tran.enquiries._id as enquiries_id from tran.enquiries inner join tran.consignor_address on tran.consignor_address._id=tran.enquiries.pickupAddresssId inner join tran.consignee_masterdata on tran.consignee_masterdata.userId=tran.enquiries.toConsigneeId
                                        #inner join tran.selected_transporters on tran.selected_transporters.enquiryId=tran.enquiries._id inner join tran.transporter_masterdata on tran.transporter_masterdata._id=tran.selected_transporters.selectedTransporterId inner join tran.users on tran.users.userId=tran.transporter_masterdata.userId left join tran.bids on tran.bids.enquiryId=tran.selected_transporters.enquiryId and tran.bids.transporterId=tran.transporter_masterdata.userId where tran.bids._id is null and tran.bids.transporterId is null and tran.bids.enquiryId is null and tran.enquiries._id={};""".format(enquiryId)

               transporter_not_bid = """select fleetosdb.transporter_masterdata.companyName,fleetosdb.users.firebaseUid,fleetosdb.consignor_address.location as consignor_location,fleetosdb.consignee_masterdata.location as consignee_location,fleetosdb.enquiries.loadingTime as pickuptime,fleetosdb.users.fcmtoken,fleetosdb.enquiries._id as enquiries_id from fleetosdb.enquiries inner join fleetosdb.consignor_address on fleetosdb.consignor_address._id=fleetosdb.enquiries.pickupAddresssId inner join fleetosdb.consignee_masterdata on fleetosdb.consignee_masterdata.userId=fleetosdb.enquiries.toConsigneeId
                                        inner join fleetosdb.selected_transporters on fleetosdb.selected_transporters.enquiryId=fleetosdb.enquiries._id inner join fleetosdb.transporter_masterdata on fleetosdb.transporter_masterdata._id=fleetosdb.selected_transporters.selectedTransporterId inner join fleetosdb.users on fleetosdb.users.userId=fleetosdb.transporter_masterdata.userId left join fleetosdb.bids on fleetosdb.bids.enquiryId=fleetosdb.selected_transporters.enquiryId and fleetosdb.bids.transporterId=fleetosdb.transporter_masterdata.userId where fleetosdb.bids._id is null and fleetosdb.bids.transporterId is null and fleetosdb.bids.enquiryId is null and fleetosdb.enquiries._id={} group by fleetosdb.selected_transporters._id;""".format(enquiryId)
               df = pd.read_sql(transporter_not_bid, engine)
               data_transporter_not_bides = df.to_dict('records')
               result["data_transporter_not_bides"] = data_transporter_not_bides
               return jsonify(result)
          else:
               
               data = df.to_json(orient="records")
               data = json.loads(data)
               print(data)
               result['Bids'] = data
               
               result['companyName'] = []
               for item in data:

                    trans = session.query(TransporterMasterData).filter(TransporterMasterData.userId == item['transporterId']).with_entities(TransporterMasterData.companyName).statement
                    df = pd.read_sql(trans, engine)
                    tranInfo = df.to_json(orient="records")
                    tranInfo = json.loads(tranInfo)
                    # print(tranInfo[0]['companyName'])

                    result['companyName'].append(tranInfo[0]['companyName'])

               enq = session.query(Enquiry).filter(Enquiry._id == enquiryId).with_entities(Enquiry.weight,Enquiry.loadingTime).statement
               df = pd.read_sql(enq, engine)
               enqData = df.to_json(orient="records")
               enqData = json.loads(enqData)
               result['enquiry'] = enqData[0]

               consignorAdrs = session.query(ConsignorAddress,Enquiry).filter(and_(ConsignorAddress._id == Enquiry.pickupAddresssId),(Enquiry._id == enquiryId)).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state,ConsignorAddress.pincode).statement
               df = pd.read_sql(consignorAdrs, engine)
               fromlocation = df.to_json(orient="records")
               fromlocation = json.loads(fromlocation)
               result['from']=fromlocation[0]

               consigneeAdrs = session.query(ConsigneeMasterData,Enquiry).filter(and_(ConsigneeMasterData.userId == Enquiry.toConsigneeId),(Enquiry._id == enquiryId)).with_entities(ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.pincode).statement
               df = pd.read_sql(consigneeAdrs, engine)
               tolocation = df.to_json(orient="records")
               tolocation = json.loads(tolocation)
               result['to']=tolocation[0]

               transporter_not_bid = """select fleetosdb.transporter_masterdata.companyName,fleetosdb.users.firebaseUid,fleetosdb.consignor_address.location as consignor_location,fleetosdb.consignee_masterdata.location as consignee_location,fleetosdb.enquiries.loadingTime as pickuptime,fleetosdb.users.fcmtoken,fleetosdb.enquiries._id as enquiries_id from fleetosdb.enquiries inner join fleetosdb.consignor_address on fleetosdb.consignor_address._id=fleetosdb.enquiries.pickupAddresssId inner join fleetosdb.consignee_masterdata on fleetosdb.consignee_masterdata.userId=fleetosdb.enquiries.toConsigneeId
                                                  inner join fleetosdb.selected_transporters on fleetosdb.selected_transporters.enquiryId=fleetosdb.enquiries._id inner join fleetosdb.transporter_masterdata on fleetosdb.transporter_masterdata._id=fleetosdb.selected_transporters.selectedTransporterId inner join fleetosdb.users on fleetosdb.users.userId=fleetosdb.transporter_masterdata.userId left join fleetosdb.bids on fleetosdb.bids.enquiryId=fleetosdb.selected_transporters.enquiryId and fleetosdb.bids.transporterId=fleetosdb.transporter_masterdata.userId where fleetosdb.bids._id is null and fleetosdb.bids.transporterId is null and fleetosdb.bids.enquiryId is null and fleetosdb.enquiries._id={} group by fleetosdb.selected_transporters._id;""".format(enquiryId)
               #transporter_not_bid = """select tran.transporter_masterdata.companyName,tran.users.firebaseUid,tran.consignor_address.location as consignor_location,tran.consignee_masterdata.location as consignee_location,tran.enquiries.loadingTime as pickuptime,tran.users.fcmtoken,tran.enquiries._id as enquiries_id from tran.enquiries inner join tran.consignor_address on tran.consignor_address._id=tran.enquiries.pickupAddresssId inner join tran.consignee_masterdata on tran.consignee_masterdata.userId=tran.enquiries.toConsigneeId
                                        #inner join tran.selected_transporters on tran.selected_transporters.enquiryId=tran.enquiries._id inner join tran.transporter_masterdata on tran.transporter_masterdata._id=tran.selected_transporters.selectedTransporterId inner join tran.users on tran.users.userId=tran.transporter_masterdata.userId left join tran.bids on tran.bids.enquiryId=tran.selected_transporters.enquiryId and tran.bids.transporterId=tran.transporter_masterdata.userId where tran.bids._id is null and tran.bids.transporterId is null and tran.bids.enquiryId is null and tran.enquiries._id={};""".format(enquiryId)


               df = pd.read_sql(transporter_not_bid, engine)
               data_transporter_not_bides= df.to_dict('records')
               result["data_transporter_not_bides"] = data_transporter_not_bides
               return jsonify(result)
               

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session          
def dbTransporterBidEnqId(transporterId,session=None):
     try:
          q = session.query(Bids).with_entities(Bids.enquiryId,Bids.advance,Bids.againstBill,Bids.estimatedDelivery,Bids.pickup,Bids.remarks,Bids.timestamp).filter(Bids.transporterId == transporterId).statement
          df = pd.read_sql(q, engine)
          # print(df)
               
          if(df.empty):
               return []
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
def dbTransporterBidDetails(bidId,session=None):
     try:
          q = session.query(Bids).filter(Bids._id == bidId).statement
          df = pd.read_sql(q, engine)
		# print(df)
          
          if(df.empty):
               return None
          else:
               result = {}
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['bid'] = data[0]

               transporterId = df['transporterId'].tolist()
               enquiryId = df['enquiryId'].tolist()

               trans = session.query(TransporterMasterData,Users).filter(and_(TransporterMasterData.userId == transporterId[0],Users.userId == transporterId[0])).with_entities(Users.firebaseUid,TransporterMasterData.companyName).statement
               df = pd.read_sql(trans, engine)
               enqData = df.to_json(orient="records")
               enqData = json.loads(enqData)
               result['companyName'] = enqData[0]['companyName']

               enq = session.query(Enquiry).filter(Enquiry._id == enquiryId[0]).statement
               df = pd.read_sql(enq, engine)
               enqData = df.to_json(orient="records")
               enqData = json.loads(enqData)
               result['enquiry'] = enqData

               consignor = session.query(ConsignorMasterData).filter(ConsignorMasterData.userId == enquiryId[0]).statement
               df = pd.read_sql(consignor, engine)
               consignor = df.to_json(orient="records")
               consignor = json.loads(consignor)
               result['consignor']=consignor

               consignorAdrs = session.query(ConsignorAddress,Enquiry).filter(and_(ConsignorAddress._id == Enquiry.pickupAddresssId),(Enquiry._id == enquiryId[0])).with_entities(ConsignorAddress.address,ConsignorAddress.location,ConsignorAddress.district,ConsignorAddress.state,ConsignorAddress.pincode).statement
               df = pd.read_sql(consignorAdrs, engine)
               fromlocation = df.to_json(orient="records")
               fromlocation = json.loads(fromlocation)
               result['from']=fromlocation

               consigneeAdrs = session.query(ConsigneeMasterData,Enquiry,Users).filter(and_(ConsigneeMasterData.userId == Enquiry.toConsigneeId),(Enquiry._id == enquiryId[0]),(Users.userId == Enquiry.toConsigneeId)).with_entities(Users.firebaseUid,ConsigneeMasterData.address,ConsigneeMasterData.location,ConsigneeMasterData.district,ConsigneeMasterData.state,ConsigneeMasterData.pincode).statement
               df = pd.read_sql(consigneeAdrs, engine)
               tolocation = df.to_json(orient="records")
               tolocation = json.loads(tolocation)
               result['to']=tolocation

               return jsonify(result)
               
     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbAcceptbid(userId,bidId,remark,session=None):
     try:
          q = session.query(Bids).filter(Bids._id == bidId).statement
          df = pd.read_sql(q, engine)
          # data = df.to_json(orient="records")
          
          q = session.query(Bids).filter(and_(Bids._id == bidId,Bids.status == 'accepted')).statement
          df1 = pd.read_sql(q, engine)

          if(df.empty):
               return None
          elif(not df1.empty):
               return 'accepted'
          else:
               enquiryId = df['enquiryId'].tolist()
               transporterId = df['transporterId'].tolist()

               data = {'status' : 'rejected','remarks':remark}
               update = session.query(Bids).filter(and_(Bids._id  != bidId),(Bids.enquiryId == enquiryId[0])).update(data)
               session.commit()
               # print('Matched rows:', update.rowcount)

               data = {'status' : 'accepted','remarks':remark}
               update = session.query(Bids).filter(and_(Bids._id  == bidId),(Bids.enquiryId == enquiryId[0])).update(data)
               session.commit()
               # print('Matched rows:', update.rowcount) 

               insertShipment = Shipments(bidId=bidId,enquiryId = enquiryId[0],transporterId = transporterId[0],requesterId = userId,tracking_status = 'Scheduled',tracking_remark=remark,tracking_postedby=userId, timestamp = datetime.now())
               session.add(insertShipment)
               session.commit()
               if(insertShipment._id):
                    return insertShipment._id
               else:
                    return 0
     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)
     
     except:
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno,exc_obj)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbRejectbid(userId,bidId,remark,session=None):
     try:
          q = session.query(Bids).filter(Bids._id == bidId).statement
          df = pd.read_sql(q, engine)
		# print(df)
          
          if(df.empty):
               return None
          else:
               enquiryId = df['enquiryId'].tolist()

               data = {'status' : 'rejected','remarks':remark}
               update = session.query(Bids).filter(and_(Bids._id  == bidId),(Bids.enquiryId == enquiryId[0])).update(data)
               session.commit()
               return 1
          

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)