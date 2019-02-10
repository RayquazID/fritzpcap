#!/usr/bin/env python2

import hashlib
import time
import sys
import requests as req
from requests.auth import HTTPDigestAuth
from xml.etree import ElementTree

print 'Starting fritzpcap_0.1...'
print 'greez from @rayquazID'

# Setup some variables
url = '' # http://Your Adress
user = '' # Your Username optional
passwd = '' # Your Password
target_path = '/home/rayquazid/fritz/datastream.pcap' # Your output location
interface ='1-lan' # Default interface


login_url = url + '/login_sid.lua'
cap_url = url + '/?lp=cap'
capture_url = url + '/cgi-bin/capture_notimeout?sid='
index_url = url + '/index.lua'
query_url = url + '/query.lua?'


headers_xml = {'Content-Type': 'text/xml'}
headers_app = {'Content-Type': 'application/x-www-form-urlencoded'}
query_sessions = 'sessions=capture:settings/session/list(displayname,ifacename,minor,type)'
query_defaults = 'dtrace=capture:settings/dtrace_running&dfileold=capture:settings/dtrace_old&dfilenew=capture:settings/dtrace_new&lte=lted:settings/trace/status&wlantrace=wlan:settings/debug_settings/trace_state&ltetrace=lted:settings/trace/enabled&xhr=1'




def fLogin():
	r = req.get(login_url, headers=headers_xml)
	if r.status_code == 200 and 'Challenge' in r.text:
		# extract challenge from HTTP Server response
		# create new response to the challenge
		# send new response to the FritzBox!
		# further infos on this: https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/Session-ID_deutsch_13Nov18.pdf
		#
		tree = ElementTree.fromstring(r.text)
		chall = tree[1].text
		chall_response = chall + '-' + passwd
		md5_chall_response = hashlib.md5(chall_response.encode('UTF-16LE')).hexdigest()
		final_response = chall + '-' + md5_chall_response

		payload = 'response=' + final_response + '&lp=&username='
		print 'Current login challenge is ' + chall
		print 'Generated final response: ' + final_response

		r = req.post(login_url, data=payload, headers=headers_app)

		if '<SID>' in r.text:
			tree = ElementTree.fromstring(r.text)
			sid = tree[0].text
			if sid != '0000000000000000':
				print 'GOT SID: '+ sid
			else:
				print 'Login Failed - no valid SID found - Try again'
				return

		print 'Login Successfull - Start Capture'
	else:
		print 'Login Failed - Try again'

	return sid

def stoppCapture():
	test = '&capture=Stop&snaplen=1600&ifaceorminor='
	r = req.get(capture_url + tmp_sid + test + interface, stream=True)
	print r.text
	print r.status_code
	return

def startpCapture():
	t_init = time.time()
	test = '&capture=Start&snaplen=1600&ifaceorminor='
	handle = open(target_path, "wb")
	r = req.get(capture_url + tmp_sid + test + interface, stream=True)
	print r.status_code
	for chunk in r.iter_content(chunk_size=512):
    		if chunk:  # filter out keep-alive new chunks
    			t_tmp = time.time()
    			t = t_tmp - t_init
    			if int(t) < int(sys.argv[1]):
	        		handle.write(chunk)
	        	else:
	        		stoppCapture()
	        		print 'Capture Stopped by timer'

	        		return
	print 'Returning from capture'
	return

tmp_sid = fLogin()
if tmp_sid != '0000000000000000':
	startpCapture()

