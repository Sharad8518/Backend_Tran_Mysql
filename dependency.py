import requests
import json
import sys
from models import * 
import pandas as pd
import smtplib
from flask_jwt_extended import ( jwt_required)
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

firebase = os.environ.get("FIREBASE_CREDENTIALS")
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


@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def pushnotification(no_of_transporter, current_identity, toConsigneeId, session=None):
    try:
        i = 0
        status=[]
        while i < len(no_of_transporter):
            query = session.query(TransporterMasterData, Users).with_entities(TransporterMasterData.userId, Users.fcmtoken).filter(
            	TransporterMasterData._id == no_of_transporter[i], Users.userId == TransporterMasterData.userId).statement
            df = pd.read_sql(query, engine)
	    
            if df.empty:
                return "Please provide fcmtoken"
            else:
                token = df['fcmtoken'].tolist()[0]
                queryConsignee = session.query(ConsigneeMasterData).with_entities(
                    ConsigneeMasterData.location).filter(ConsigneeMasterData._id == toConsigneeId).statement
                dfconsignee = pd.read_sql(queryConsignee, engine)
                location = dfconsignee['location'].tolist()
		
                queryconsignor = session.query(ConsignorMasterData).with_entities(
                    ConsignorMasterData.companyName).filter(ConsignorMasterData.userId == current_identity).statement
                dfconsignoor = pd.read_sql(queryconsignor, engine)
                company_name = dfconsignoor["companyName"].to_list()
		
                serverToken = firebase
                deviceToken = token
        
                headers = {
                    'Content-Type': 'application/json',
                    'Authorization': 'key=' + serverToken,
                }
                title = 'Tran logistics'
                messagedata = f'{company_name[0].upper()} has generated enquiry for {location[0].upper()}.Please bid!'
                body = {
                    'notification': {'title': title,
                            'body': messagedata
                            },
                    'to':
                    deviceToken,
                    'priority': 'high',
                    #   'data': dataPayLoad,
                }
        
                response = requests.post(
                    "https://fcm.googleapis.com/fcm/send", headers=headers, data=json.dumps(body))
                data = f'the status code for {no_of_transporter[i]} transporter is {response.status_code} '
                status.append(data)
                i+=1
        return status

    except:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            return ({'success': False, 'message': 'Something went wrong!'}), 400


@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def bidpushnotification(enquiryId, identity,status, session=None):
		try:
			query = session.query(Enquiry, Bids, TransporterMasterData, Users,ConsigneeMasterData).with_entities(ConsigneeMasterData.location,Bids.rate, TransporterMasterData.companyName, Users.fcmtoken).filter(Enquiry._id==Bids.enquiryId,TransporterMasterData.userId==Bids.transporterId,ConsigneeMasterData.userId==Enquiry.toConsigneeId,Users.userId==Enquiry.enquiryBy,Bids.transporterId==identity,Enquiry._id==enquiryId).statement
			
			df = pd.read_sql(query, engine)

			location = df["location"].tolist()
			rate = df["rate"].tolist()
			companyName = df["companyName"].tolist()
			fcmtoken = df["fcmtoken"].tolist()
			serverToken = firebase
			deviceToken = fcmtoken[0]
			headers = {
				'Content-Type': 'application/json',
				'Authorization': 'key=' + serverToken,
			}
			print("servertoken",serverToken)
			title = 'Tran logistics'
			if status == "normal":
				messagedata = f'{companyName[0]} has offered Rs {rate[0]} for {location[0]}.'
			else:
				messagedata = f'{companyName[0]} has revised rate to Rs {rate[0]} for {location[0]}.'
			body = {
					'notification': {'title': title,
										'body': messagedata
										},
					'to':
					deviceToken,
					'priority': 'high'
                    }

			response = requests.post(
				"https://fcm.googleapis.com/fcm/send", headers=headers, data=json.dumps(body))
			print(response.status_code)
			return response.status_code

		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400


@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def bidAcceptedNotification(bidId, session=None):
	try:
		query = session.query(Enquiry, Bids, TransporterMasterData, Users, ConsigneeMasterData).with_entities(ConsigneeMasterData.location,ConsignorMasterData.companyName, Users.fcmtoken,Bids.pickup).filter(
			Bids._id==bidId,Users.userId==Bids.transporterId,Enquiry._id==Bids.enquiryId,ConsignorMasterData.userId==Enquiry.enquiryBy,ConsigneeMasterData.userId==Enquiry.toConsigneeId).statement

		df = pd.read_sql(query, engine)
		print("red:",df)

		location = df["location"].tolist()
		pickup = df["pickup"].tolist()
		companyName = df["companyName"].tolist()
		fcmtoken = df["fcmtoken"].tolist()
		
		serverToken = firebase
		deviceToken = fcmtoken[0]
		headers = {
			'Content-Type': 'application/json',
			'Authorization': 'key=' + serverToken,
		}

		title = 'Tran logistics'
		messagedata = f'{companyName[0]},has ordered truck for {location[0]}, for loading on {pickup[0]}.'
		# Company has ordered truck for # Location for loading on # Date
		body = {
						'notification': {'title': title,
					'body': messagedata
					},
				'to':
				deviceToken,
				'priority': 'high'
						}

		response = requests.post(
			"https://fcm.googleapis.com/fcm/send", headers=headers, data=json.dumps(body))
		print(response.status_code)
		return response.status_code

	except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
			return ({'success': False, 'message': 'Something went wrong!'}), 400


@retry_db((OperationalError, StatementError), n_retries=30)
@mk_session
def messageNotification(sendMessage, firebase_id, sender_name, session=None):
	try:
		print(firebase_id,sendMessage,sender_name)
		query = session.query(Users).with_entities(Users.fcmtoken).filter(Users.firebaseUid == firebase_id).statement
		df = pd.read_sql(query, engine)
		fcmtoken = df["fcmtoken"].tolist()
		serverToken = firebase
		print(fcmtoken[0])
		deviceToken = fcmtoken[0]
	
		headers = {
			'Content-Type': 'application/json',
			'Authorization': 'key=' + serverToken,
		}

		body = {
			'notification': {'title': sender_name,
                            'body': sendMessage
							},
			'to':
			deviceToken,
			'priority': 'high',
			#   'data': dataPayLoad,
		}

		response = requests.post(
			"https://fcm.googleapis.com/fcm/send", headers=headers, data=json.dumps(body))
		print(response.text, response.status_code)
		return response.status_code


	except:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		return ({'success': False, 'message': 'Something went wrong!'}), 400
	
MAIL_USERNAME="ssinghster7@gmail.com"
MAIL_PASSWORD="5GhpBmSa2UVZYCjI"
MAIL_FROM="ssinghster7@gmail.com"
MAIL_PORT="587"
MAIL_SERVER="smtp-relay.sendinblue.com"
MAIL_STARTTLS="False"
MAIL_SSL_TLS="False"
MAIL_USE_CREDENTIALS="True"
MAIL_VALIDATE_CERTS="True"


def sendEmailNotifiction(email, material, weight, TruckType, consignor, companyName):
	try:
		port = MAIL_PORT
		smtp_server = MAIL_SERVER
		login = MAIL_USERNAME  # paste your login generated by Mailtrap
		password = MAIL_PASSWORD  # paste your password generated by Mailtrap
		sender_email = "contact@tran.co.in"
		receiver_email = email
		message = MIMEMultipart("alternative")
		message["Subject"] = "Order Delivered!"
		message["From"] = sender_email
		message["To"] = receiver_email
		# write the text/plain part
		text = """\
		Hi,

		We’re delighted to let you know that your order has been successfully delivered.

		Following dispatch has been done to your company.

		Consignor: {}
		Material: {}
		weight: {}
		TruckType: {}
		companyName: {}

		""".format(consignor,material,weight, TruckType, companyName)
		# convert both parts to MIMEText objects and add them to the MIMEMultipart message
		part1 = MIMEText(text, "plain")
		message.attach(part1)
		# send your email
		with smtplib.SMTP(smtp_server, port) as server:
			server.login(login, password)
			server.sendmail(
					sender_email, receiver_email, message.as_string())
		print('Sent')
		return "success"
	except Exception as e:
		print(e)
		