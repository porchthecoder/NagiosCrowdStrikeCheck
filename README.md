# NagiosCrowdStrikeCheck
Nagios check to query the CrowdStrike API for current host checkin status

When run as a service check in Nagios, this Python3 script queries the CrowdStrike API for last host check in time. If the host has not checked into CrowdStrike within the last 2 hours, then the script returns the Critical status to Nagios. 
The intended purpose of this script is to validate servers have CrowdStrike installed on them, and that it is functional and checking into the CrowdStrike Cloud. 

# Requirements
* Python 3
* FalconSDK (see CrowdStrike API docs on instructions on how to install this) 
* Python sqlite3 library. 
* Nagios

# Technical Details
The CrowdStrike API limits how often it can be called, and how often a auth token can be generated, along with normal API slowness. This does not play well with how Nagios does service checks. To overcome this limitation, this script is broken into two logical sections. 

* When Nagios does a service check (calls this script with -H), this script does a lookup of the host in an sqlite3 database. It returns the status as reported by the sqlite3 database, not current status by CrowdStrike. If the host does not exist, then it returns unknown and adds the host to the sqlite3 database for future lookup. 

* A cron job calls this script with the "-U now" option. This causes the script to query the CrowdStrike API and update all the host in the sqlite3 database. The CrowdStrike host ID is added to the database and is used for all future lookups from the CrowdStrike API as this saves a API call for the host name to host ID with every update.  

By using a local sqlite3 database for last known status, Nagios can easly query current status as much as needed without maxing out the CrowdStrike API. 


# Install Instructions. 
 * Install the install requirements. 
 * Copy this script into the /etc/nagios/plugins directory and adjust permissions so that Nagios can execute it. 
 * The sqlite3 database location can be changed, but it needs to be in a location that the user Nagios can read/write. The default of /var/spool/nagios/ seems to work. 
 * Update the CrowdStrike client_id and client_secret using the information provided by the API section in CrowdStrike. Read only access to the host information is all that is needed for permissions. 
 * For testing, run the script with "-H webserver1" (with webserver1 being a valid host in CrowdStrike). It should return unknown. Then run the script with "-U now". It should query the API and do nothing. If no error, run it again with "-H webserver1". It should not return a OK status. 
 * Add it as a service check to Nagios using the example. 
* Add a crontab entry to run the script with the “-U now” option every 15-30 minutes.

# Notes on the CrowdStrike API and host names. 
The CrowdStrike API “filter” for host names is case sensitive for some unknown reason. If the host in CrowdStrike has the name “WEBSERVER1” but the Nagios configuration has “webserver1”, the host lookup will fail.  The script will do a API lookup with whatever case Nagios has, along with an all upper and all lower case.  This works most of the time, but if the host name is CamelCase, this will fail.  In addition, by default, the domain name may also be appended to the host name. An example is given in the filter section of the code on how to append domain names. 




