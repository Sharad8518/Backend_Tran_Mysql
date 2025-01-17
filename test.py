import requests
import json
import sys
import pandas as pd
import MySQLdb
firebase = "AAAAzaP4EYE:APA91bGf9U0El34AEpy5rT5l6VgELVLAEuBxfkO8s-aJPe6_KQT9Zv3-i169eUGf22XHoQOc777xBq6r2CbKAADiXrWOABIbU6mUxRDkIIVRlj5mW8s5Y44G6cme6KahIuHiV3hh33FH"
db = MySQLdb.connect(host="localhost",    # your host, usually localhost
                     user="fleetos",         # your username
                     passwd="fleetos@1234",  # your password   tran851890
                     db="fleetosdb")        # name of the data base

# db = MySQLdb.connect(host="localhost",    # your host, usually localhost
#                     user="tran",         # your username
#                     passwd="tran1234",  # your password
#                     db="trandb")

def sendnotification():
	try:
		#query = "select tran.enquiries._id as enquiry_id,tran.enquiries.enquiryBy, tran.enquiries.pickupAddresssId,tran.selected_transporters._id as selected_transporters_id,tran.selected_transporters.enquiryId as selected_transporters_enquiryId,tran.selected_transporters.selectedTransporterId,tran.enquiries.toConsigneeId,tran.users.fcmtoken, tran.consignor_masterdata.companyName,tran.consignee_masterdata.location, tran.selected_transporters.selectedTransporterId,tran.bids._id as bids_id,tran.bids.transporterId,tran.bids.enquiryId,tran.transporter_masterdata.userId as transporter_masterdata_userId  from tran.enquiries inner join tran.selected_transporters on tran.selected_transporters.enquiryId=tran.enquiries._id inner join tran.consignee_masterdata on tran.consignee_masterdata.userId=tran.enquiries.toConsigneeId inner join tran.consignor_masterdata on tran.consignor_masterdata.userId=tran.enquiries.enquiryBy inner join tran.transporter_masterdata on tran.transporter_masterdata._id=tran.selected_transporters.selectedTransporterId inner join tran.users on tran.users.userId=tran.transporter_masterdata.userId left join tran.bids on tran.bids.enquiryId=tran.selected_transporters.enquiryId where tran.enquiries.timestamp>(current_date()-interval 3 day) and tran.bids._id is null and tran.bids.transporterId is null and tran.bids.enquiryId is null;"
		query = "select fleetosdb.enquiries._id as enquiry_id,fleetosdb.enquiries.enquiryBy, fleetosdb.enquiries.pickupAddresssId,fleetosdb.selected_transporters._id as selected_transporters_id,fleetosdb.selected_transporters.enquiryId as selected_transporters_enquiryId,fleetosdb.selected_transporters.selectedTransporterId,fleetosdb.enquiries.toConsigneeId,fleetosdb.users.fcmtoken, fleetosdb.consignor_masterdata.companyName,fleetosdb.consignee_masterdata.location, fleetosdb.selected_transporters.selectedTransporterId,fleetosdb.bids._id as bids_id,fleetosdb.bids.transporterId,fleetosdb.bids.enquiryId,fleetosdb.transporter_masterdata.userId as transporter_masterdata_userId  from fleetosdb.enquiries inner join fleetosdb.selected_transporters on fleetosdb.selected_transporters.enquiryId=fleetosdb.enquiries._id inner join fleetosdb.consignee_masterdata on fleetosdb.consignee_masterdata.userId=fleetosdb.enquiries.toConsigneeId inner join fleetosdb.consignor_masterdata on fleetosdb.consignor_masterdata.userId=fleetosdb.enquiries.enquiryBy inner join fleetosdb.transporter_masterdata on fleetosdb.transporter_masterdata._id=fleetosdb.selected_transporters.selectedTransporterId inner join fleetosdb.users on fleetosdb.users.userId=fleetosdb.transporter_masterdata.userId left join fleetosdb.bids on fleetosdb.bids.enquiryId=fleetosdb.selected_transporters.enquiryId and fleetosdb.bids.transporterId=fleetosdb.transporter_masterdata.userId where fleetosdb.enquiries.timestamp>(current_date()-interval 3 day) and fleetosdb.bids._id is null and fleetosdb.bids.transporterId is null and fleetosdb.bids.enquiryId is null;"
		cur = db.cursor()
		cursor = cur.execute(query)
		for row in cur.fetchall():
			print(row)
			location = row[9]
			companyName = row[8]
			fcmtoken = row[7]


			serverToken = firebase
			deviceToken = fcmtoken
			headers = {
					'Content-Type': 'application/json',
							'Authorization': 'key=' + serverToken,
				}

			title = 'Tran logistics'
			messagedata = f'Please bid for enquiry of {companyName} for {location}'
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
			print(response.status_code,companyName)
		cur.close()
	except:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		return ({'success': False, 'message': 'Something went wrong!'}), 400

sendnotification()



