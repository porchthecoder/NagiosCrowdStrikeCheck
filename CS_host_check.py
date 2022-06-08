#!/usr/bin/python3
import json
import datetime
import pytz
import sqlite3
import sys
import argparse
import time

from datetime import datetime, timedelta
from falconpy import api_complete as FalconSDK


#NagiosCrowdStrikeCheck V1.0 8/16/21
#Checks the status of a host in the CS cloud. Interfaces with Nagios as a command to check host
#This script uses the CrowdStrike Python3 API modules. 
#Calling this script with -H <hostname> returns the host status in the sqlite database. 
#Calling this script with -U now, updates the sqlite database with information from CS. 
#This is not real time information from CS. The sqlite database holds current status for Nagios, and the sqlite database is updated (batch style) from CS hourly (crontab). 
#CS API is slow and designed to be batched, so we need the sqlite database in the middle to keep Nagios fast and not rate limit the API. 

#The sqlite database can be deleted, and it will be rebuilt and repopulated. 
#On the first time a host is seen, with -H <hostname>, it is added to the sqlite database with an unkown status. When the crontab calls this script with -U now, it will update it's status. 
#If this script can not access the CS cloud, the server will go into an "unknown" status. 

#V1.1 9/16/21
#Added the -D (Delete) and -B (Bad) option.

#V1.2 10/6/21
#Added to code to check the host hidden status, and remove the host from the database if hidden. This will handle the use case of the falcon agent being reinstalled and the old host deleted from CS. 


local_tz = pytz.timezone('America/Los_Angeles')
con_sql = sqlite3.connect('/var/spool/nagios/CS_hosts_check.sqlite')
#See below for the CrowdStrike URL and auth id. 

#con_sql = sqlite3.connect('./CS_hosts_api.sqlite') #For Debugging only.
cur_sql = con_sql.cursor()

# Setup Arguments
parser = argparse.ArgumentParser(description='Nagios plugin for CrowdStrike API host lookup')
parser.add_argument("-H", "--Host", help = "Host to get status on")
parser.add_argument("-U", "--Update", help = "Update CS status on all host in database. Must be passed with -U now ")
parser.add_argument("-D", "--Delete", help = "Delete a host from the database")
parser.add_argument("-B", "--Bad", help = "Delete all host in an none OK state. Use for database cleanup. Must be called with -B sure")

args = parser.parse_args()



#Create the object for the calls
falcon = FalconSDK.APIHarness(creds={
	'client_id': '<INSERT ID HERE>',
	'client_secret': '<INSERT SECRET HERE>'
},
	base_url = "https://api.us-2.crowdstrike.com"	# Enter your base URL here if it is not US-2
)

def get_host_sql(hostname): #Get info about the host
	cur_sql.execute("SELECT * from hosts WHERE hostname = '"+hostname+"' limit 1")
	resualts=cur_sql.fetchone()
	return(resualts)


def add_new_host(hostname): #Insert the hostname into the database, if not exist. 
	unix_time = str(int(time.time()))
	cur_sql.execute("INSERT INTO hosts VALUES ('"+hostname+"','UNKNOWN - New host. Have not bugged CrowdStrike about it yet.','UNKNOWN',null,"+unix_time+")")
	con_sql.commit()


def remove_stale_host(): #delete any records that have not been quered with the -H option for 30 days
	print("Removing stale host")
	unix_time = str(int(time.time()-2592000)) #seconds minus 30days
	cur_sql.execute("DELETE FROM hosts WHERE unixtime <= "+unix_time+"")
	con_sql.commit()

def remove_bad_host(): #delete any records not in OK status. This helps cleanup the database. 
	print("Removing host in UNKNOWN or CRITIAL status")
	cur_sql.execute("DELETE FROM hosts WHERE status != 'OK'")
	con_sql.commit()



def utc_to_local(utc_dt): 
	local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
	return local_tz.normalize(local_dt) # .normalize might be unnecessary

def update_all(): #Update all the host with information from the CS api
	cur_sql2 = con_sql.cursor()
	cur_sql2.execute('SELECT hostname FROM hosts')
	rows = cur_sql2.fetchall()
	for row in rows:
		print(row[0])
		query_CS(row[0])

#This entire function needs to be broken up into sub functions. It's growing out of control. 
def query_CS(hostname):

	cur_sql.execute("SELECT hostid from hosts WHERE hostname = '"+hostname+"' limit 1")
	resualts=cur_sql.fetchone()
	host_id=str(resualts[0])
	
	##Get the CW host_id number if it does not exist. We use this id number for future lookups so we don't have to query the CS api twice. 
	if (host_id == "None"):
		print("Unkown server, trying to get the CS host ID");
		PARAMS = {

		'filter': "hostname:['"+hostname.upper()+"','"+hostname.lower()+"','"+hostname+"']" #Try both upper and lower case
		# EXAMPLE WITH DOMAINNAME 'filter': "hostname:['"+hostname.upper()+"','"+hostname.lower()+"','"+hostname.lower()+".company.com','"+hostname.upper()+".COMPANY.COM','"+hostname.lower()+".INTERNAL.INFO','"+hostname.upper()+".INTERNAL.INFO']" 

		}
		response = falcon.command('QueryDevicesByFilter', parameters=PARAMS)
		#print(json.dumps(response, indent=4, sort_keys=True))

		#Check for the status code. If not 200, then something went wrong. 
		if (response['status_code'] != 200):
			#print("Error")
			#print(json.dumps(response, indent=4, sort_keys=True))
			cur_sql.execute("UPDATE hosts SET text = 'UNKNOWN - Server "+hostname+" Unknown Status. CrowdForce Cloud return error code "+str(response['status_code'])+" ', status = 'UNKNOWN' WHERE hostname = '"+hostname+"'")
			con_sql.commit()
			return

		str_body=str(len(response['body']['resources']))
	
		#Check to see if the host exist
		if (len(response['body']['resources']) == 0):
			#print("Host "+hostname+" not found")
			cur_sql.execute("UPDATE hosts SET text = 'CRITICAL - Server "+hostname+" not in CrowdStrike', status = 'CRITICAL' WHERE hostname = '"+hostname+"'")
			con_sql.commit()
			return

		host_id = str(response['body']['resources'][0]);

		
	response = falcon.command('GetDeviceDetails', ids=host_id)
	#print(json.dumps(response, indent=4, sort_keys=True))

	#Check for the status code. If 404, then the server can not be found. Wipe out the hostid from the sql database and set it to unknown.
	#Next refresh will search for the host_id by the hostname again. We don't do it now because A) extra code, and B) gives time for the server to checkin and update.
	if (response['status_code'] == 404):
		print("Error404")
		print(json.dumps(response, indent=4, sort_keys=True))
		cur_sql.execute("UPDATE hosts SET text = 'UNKNOWN - Server "+hostname+" Unknown Status. Server was in CrowsStrike, but no longer found. Resetting status and will try to find it again on next refresh.', status = 'UNKNOWN', hostid = null WHERE hostname = '"+hostname+"'")
		con_sql.commit()
		return


	#Check for the status code. If not 200, then something went wrong. 
	if (response['status_code'] != 200):
		#print("Error")
		#print(json.dumps(response, indent=4, sort_keys=True))
		cur_sql.execute("UPDATE hosts SET text = 'UNKNOWN - Server "+hostname+" Unknown Status. CrowdForce Cloud return error code "+str(response['status_code'])+" ', status = 'UNKNOWN' WHERE hostname = '"+hostname+"'")
		con_sql.commit()
		return


	#print("Checking to see if host is deleted") 
	#If the host is set to hidden in CS, then it's deleted in CS.
	#Delete it from the database
	#If Falcon was reinstalled, the next -H <hostname>, will put it back into the database, and the next -U now call will update the database with the new host id
	#This in affect, handles the falcon client being reinstalled. But the old host needs to be deleted from CS first. 
	try:
		host_hidden_status = response['body']['resources'][0]['host_hidden_status'];
		if host_hidden_status == "hidden":
				print("Host disabled in CS. Deleting it from the database.")
				cur_sql.execute("DELETE FROM hosts WHERE hostid = '"+str(host_id)+"'")
				con_sql.commit()
				return
	except KeyError:
		pass
		#print("Host Visable")


	#CW returns a different string as a datetime. Convert it to a datatime object. 
	last_seen = response['body']['resources'][0]['last_seen'];
	date_object = datetime.strptime(last_seen, '%Y-%m-%dT%H:%M:%SZ')
	#2021-08-12T23:26:18Z

	###Convert timezone of CS date to localtime
	last_seen_local = utc_to_local(date_object)
	last_seen_local_human = last_seen_local.strftime("%Y-%m-%d %H:%M:%S")

	#Get an older date to compair to
	older_date_time = local_tz.localize(datetime.now()) - timedelta(hours = 2) 

	#print(last_seen_local)

	if last_seen_local<older_date_time:
		#print(json.dumps(response, indent=4, sort_keys=True))
		cur_sql.execute("UPDATE hosts SET text = 'CRITICAL - Server "+hostname+" not checked in to CS in 2 hours. Last checkin was "+str(last_seen_local_human)+". CS host ID="+str(host_id)+"', status = 'CRITICAL', hostid='"+host_id+"' WHERE hostname = '"+hostname+"'")
		con_sql.commit()

	else:
		#print("Server "+hostname+" Healthy. Last checked in at "+str(last_seen_local))
		cur_sql.execute("UPDATE hosts SET text = 'OK - Server "+hostname+" Healthy. Last checked in at "+str(last_seen_local_human)+". CS host ID="+str(host_id)+"', status = 'OK', hostid='"+host_id+"' WHERE hostname = '"+hostname+"'")
		con_sql.commit()
	return


def delete_host(hostname): 
	print("Removing host:" + str(hostname))
	cur_sql.execute("DELETE FROM hosts WHERE hostname = '"+str(hostname)+"'")
	con_sql.commit()


#setup the database if not exist. 
cur_sql.execute('''CREATE TABLE IF NOT EXISTS hosts (hostname, text, status, hostid, unixtime)''')
con_sql.commit()


#Check the host status. 
if args.Host:
	results = get_host_sql(args.Host)
	if not results:
		add_new_host(args.Host)

	results = get_host_sql(args.Host)
	print(results[1]);
	if (results[2] == "OK"):
		sys.exit(0)
	elif (results[2] == "CRITICAL"):
		sys.exit(2)
	elif (results[2] == "UNKNOWN"):
		sys.exit(3)
	else: 
		sys.exit(2) #Assume Critical if somethine else fails


#Update all host
if args.Update:
	if (args.Update == "now"):
		print("Updating CrowdStrike Data")
		update_all()
		#remove_stale_host() #See comment above. 

#Remove bad host
if args.Bad:
	if (args.Bad == "sure"):
		remove_bad_host()


#Delete the host status. 
if args.Delete:
	if (args.Delete != ""):
		delete_host(args.Delete)


falcon.deauthenticate()
con_sql.commit()
con_sql.close()
