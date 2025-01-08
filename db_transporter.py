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
# from passlib.hash import pbkdf2_sha256 as sha256
from datetime import datetime, timedelta
import secrets
import sys
from firebase_admin import auth
from sqlalchemy import delete

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
def dbTransporterAddRoutes(transporterId,transporterRoutes,session=None):
     try:
          userId = transporterId
          if(len(transporterRoutes)>0 ):
               for r in transporterRoutes:
                    print(r)
                    q1 = session.query(TransporterRoutes).filter(and_(TransporterRoutes.userId == userId),(TransporterRoutes.toAddress == r['toAddress']),(TransporterRoutes.fromAddress == r['fromAddress'])).statement
                    df = pd.read_sql(q1, engine)
                    # print(df)
                    if(df.empty):
                         addRoutes = TransporterRoutes(userId = userId,toAddress = r['toAddress'],fromAddress = r['fromAddress'])
                         session.add(addRoutes)
                         session.commit()
                    
                         if(not addRoutes):
                              return ({'success':False,'message':'Error in adding routes'}),400
                    
               return jsonify(success=True,msg='Transporter routes inserted successfully!')
          
     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)


@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTransporterUpdateRoutes(transporterId,transporterRoutes,session=None):
          try:
               userId = transporterId
               
               if(len(transporterRoutes)>0 ):

                    session.query(TransporterRoutes).filter(TransporterRoutes.userId == userId).delete()
                    session.commit()

                    for r in transporterRoutes:
                         
                         addRoutes = TransporterRoutes(userId = userId,toAddress = r['toAddress'],fromAddress = r['fromAddress'])
                         session.add(addRoutes)
                         session.commit()

                         if(not addRoutes):
                                   return ({'success':False,'message':'Error in adding routes'}),400
                         
                    return jsonify(success=True,msg='Transporter routes updated successfully!')

		
          except exc.SQLAlchemyError as err:
               error = str(err.__dict__['orig'])
               print("error:"+error)
                

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTransporterAccount(userId,session=None):
     try:
          result = {}

          q1 = session.query(TransporterMasterData,Users).filter(and_(TransporterMasterData.userId == userId,Users.userId == userId)).statement
          df = pd.read_sql(q1, engine)
          
          # print(df)
          
          if(df.empty):
               output = {}
               output['success'] = False
               output['msg'] = 'Transporter profile not found!'
               return jsonify(output)
          else:
               data = df.to_json(orient="records")
               data = json.loads(data)
               result['transporter'] = data
               
               q2 = session.query(TransporterRoutes).filter(TransporterRoutes.userId == userId).statement
               df2 = pd.read_sql(q2, engine)
               
               if(not df2.empty):
                    data = df2.to_json(orient="records")
                    data = json.loads(data)
                    result['routes'] = data
               
               
               return jsonify(result)

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)


@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTransporterList(userId,toRoute,fromRoute,session:None):
     try: 
          q = session.query(TransporterRoutes).with_entities(TransporterRoutes.userId).filter(and_(TransporterRoutes.toAddress == toRoute),(TransporterRoutes.fromAddress == fromRoute)).statement
          df = pd.read_sql(q, engine)

          Includetransporterlist=session.query(IncludeTransporterList,TransporterMasterData,TransporterRoutes).filter(IncludeTransporterList.consignorId==userId,TransporterMasterData._id==IncludeTransporterList.userId,TransporterRoutes.userId==TransporterMasterData.userId,TransporterRoutes.toAddress==toRoute,TransporterRoutes.fromAddress==fromRoute).with_entities(TransporterMasterData.userId).statement
          Inctranslistdata = pd.read_sql(Includetransporterlist, engine)

          allData=[]
          if Inctranslistdata.empty:
                pass
          else:
               userIdData = Inctranslistdata.to_json(orient="records")
               userIdDataJson = json.loads(userIdData)

               k=0
               while k<len(userIdDataJson):
                    input=int(userIdDataJson[k]["userId"])
                    allData.append(input)
                    k+=1

          if(df.empty):
               pass 
          else:
               data = df.to_json(orient="records")
               userData = json.loads(data)

               l=0
               while l<len(userData):
                    takeinput=int(userData[l]["userId"])
                    if takeinput in allData:
                          pass 
                    else:
                         allData.append(takeinput)
                    l+=1
          
          result=[]
          if(len(allData)>0 ):
               
               for u in allData:
                    q = session.query(TransporterMasterData).with_entities(TransporterMasterData._id,TransporterMasterData.companyName).filter(TransporterMasterData.userId == u).statement
                    
                    df = pd.read_sql(q, engine)
                    data = df.to_json(orient="records")
                    data = json.loads(data)
                    result.append(data)
               
               return jsonify(result)
          return []

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTruckTypeList(session:None):
     try:
          q = session.query(TruckType).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return None
          else:
               data = df.to_json(orient="records")
               list = json.loads(data)
     
               return jsonify(list)

     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTransporterProfileDetails(userId,session:None):
     try:
          q = session.query(TransporterMasterData).filter(TransporterMasterData.userId == userId).with_entities(TransporterMasterData.companyName,TransporterMasterData.address,TransporterMasterData.userName,TransporterMasterData.truckCount,TransporterMasterData.panNumber,TransporterMasterData.gstNumber).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return None
          else:
               data = df.to_json(orient="records")
               data = json.loads(data)

               q = session.query(TransporterRoutes).filter(TransporterRoutes.userId == userId).with_entities(TransporterRoutes.fromAddress,TransporterRoutes.toAddress).statement
               df = pd.read_sql(q, engine)
               routes = df.to_json(orient="records")
               routes = json.loads(routes)
               

               return jsonify(profile=data ,routes=routes)

     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTransporterProfileUpdate(userId,companyName,userName,address,truckCount,panNumber,gstNumber,session:None):
     try:
          q = session.query(TransporterMasterData).filter(TransporterMasterData.userId == userId).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return None
          else:
               
               data = {'companyName':companyName,'userName':userName,'address':address,'truckCount':truckCount,'panNumber':panNumber,'gstNumber':gstNumber}
               update = session.query(TransporterMasterData).filter(TransporterMasterData.userId  == userId).update(data)
               session.commit()
               return 'success'


     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)

@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def updateIncludeList(trasporterList,userId,session:None):
     try:
          q=session.query(IncludeTransporterList).filter(IncludeTransporterList.consignorId  == userId).statement
          df = pd.read_sql(q, engine)
          len_of_list=len(trasporterList)
          print("Q:",q)
          if df.empty:
               i=0
               print("lenghtqqq:",len_of_list)
               while i<len_of_list:
                    print("userId:",userId,type(userId))
                    # q = session.query(ConsignorMasterData).filter(ConsignorMasterData.userId == userId).statement
                    # df = pd.read_sql(q, engine)
                    # ConsignorData = df.to_json(orient="records")
                    # Data = json.loads(ConsignorData)
                    # print("data:",Data)

                    Data1=trasporterList[i]["_id"]
                    Data2=trasporterList[i]["userName"]
                    includeTransporter=IncludeTransporterList(
                            consignorId=userId,
                            userId=Data1,
                            userName=Data2
                    )
                    session.add(includeTransporter)
                    i+=1
               session.commit()
               
               return "Data saved!"
          else:
               j=0
               IncludeTran_data=session.query(IncludeTransporterList).filter(IncludeTransporterList.consignorId  == userId).delete()
               session.commit()
               while j<len_of_list:
                    includeTransporter=IncludeTransporterList(
                         consignorId=userId,
                         userId=trasporterList[j]["_id"],
                         userName=trasporterList[j]["userName"]
                    )
                    session.add(includeTransporter)
                    j+=1
               session.commit()
               return "Data updated!"
      
     except exc.SQLAlchemyError as err:
          error = str(err.__dict__['orig'])
          print("error:"+error)


@retry_db((OperationalError,StatementError),n_retries=30)
@mk_session
def dbTransporterroutes(userId,session:None):
     try:
          q = session.query(TransporterRoutes).filter(TransporterRoutes.userId == userId).statement
          df = pd.read_sql(q, engine)
          
          if(df.empty):
               return []
          else:
               routes = df.to_json(orient="records")
               routes = json.loads(routes)
               return routes
     except Exception as e:
          print(e)
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          print(exc_type, fname, exc_tb.tb_lineno)