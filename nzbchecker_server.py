import time
import sys
import re
import getopt
import nntp
import nntplib
import beautifulsoup
from operator import itemgetter
import socket
import ssl
import threading
import HTMLParser
import string
import cgi
import signal
import subprocess
import math

DEBUG = 1
MAXREPEAT = 3
TIMEOUT = 5
BLOCKAPPROX = 2
completion_counter = 0
completion_counter_allout = -1
lock = threading.Lock()

class TelnetConnection():

	def __init__(self, conf, idx):
		self.conf = conf
		self.idx = idx
		
	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

	def init_and_stat(self, msg):
		self.tn = nntp.NNTP(self.conf['host'], 443, self.conf['user'], self.conf['pass'], True)
		#~ print self.tn.welcome
		self.stat_all(msg)

		try:
			self.tn.quit()
		except Exception as e:
			#~ print "Error disconnecting: "  + " %s" % e,
			print "d",
			
		if(self.idx == self.conf['connections']-1):
			with lock:
				global completion_counter_allout
				completion_counter_allout = self.idx


	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

	def stat_all(self, msg):
		lastgrp = ''

		#~ for info in infodata['detail']:
		#~ if(info[2] == 0 or info[2] == 1 or info[2] == 4):


		for m in msg['detail']:			
			if(m[2] == 0 or m[2] == 1 or m[2] == 4):			
				#~ simple semaphor
				if(m[5] != -3):
					continue
				with lock:
					global completion_counter
					completion_counter += 1				
				m[5] = -1
				repeat = MAXREPEAT
				while (repeat):
					try:
						if(lastgrp != m[4][0]):
							lastgrp = m[4][0]
							self.tn.group(m[4][0])
							#~ print 'change grp'
							
						self.tn.stat("<"+m[3]+">")
						m[5] = 1
						repeat = 0
					except Exception as e:	
						error = nntp.get_error_code(e)
						if error == '430':
							#~ print "Missing article " + m[3] + " : %s" % e
							print "*",
							m[5] = 0
							repeat = 0
						else:
							#~ print "Error ("+ str(repeat) +" more attempts, trying again: " + m[3] + " %s" % e
							print "e",
							repeat -= 1

	

#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

class HealthChecker():

	def __init__(self, data):
		self.data = data.encode('utf-8')
		self.STATUS_OK = 1
		self.STATUS_MISS = 0
		self.STATUS_ERROR = -1
		self.STATUS_PAR2UNMATCHED = -4
		self.STATUS_UNKNOWN = -2
		self.STATUS_INIT = -3
				
		self.MSGTYPE_ARCHIVE = 0
		self.MSGTYPE_PAR2IDX = 1
		self.MSGTYPE_PAR2VOL = 4
		self.MSGTYPE_NFO = 2
		self.MSGTYPE_SFV = 3
		self.MSGTYPE_NZB = 5
	
		self.infodata={}
		self.getnzbinfo(data)
		self.blocksize = 0
		
	
	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 
	
	def getsmallest_healthy_par(self):
		
		cursmallest = len(self.infodata['detail'])
		smallest_par_segment = []
		segmentstr = '<segment bytes="$bytes" number="$num">$mid</segment>'
		count = 1
		subject = ''
		group = ''
		#~ get smallest vol
		for info in self.infodata['detail']:
			if(info[6] < cursmallest):
				if((info[2] == self.MSGTYPE_PAR2VOL or info[2] == self.MSGTYPE_PAR2IDX) and info[5] == self.STATUS_OK):
					cursmallest = info[6]

		#~ get all segments
		segs = ''
		for info in self.infodata['detail']:
			if(cursmallest == -2):
				if(info[2] == 1):
					s = string.Template(segmentstr).substitute({'bytes':info[1], 'num':count, 'mid':cgi.escape(info[3], quote=True)})
					subject = info[0]
					group = info[4][0]
					segs += s + '\r\n'
					count = count + 1
					
			if(info[6] == cursmallest):
				if(info[2] == 4 and info[5] == 1 ):
					s = string.Template(segmentstr).substitute({'bytes':info[1], 'num':count, 'mid':cgi.escape(info[3], quote=True)})
					subject = info[0]
					group = info[4][0]
					segs += s + '\r\n'
					count = count + 1
		
		print ''
		if(len(subject) == 0):
			print 'There is no healthy PAR2!'
			return -1
		
		print 'Get info from: ' + cgi.escape(subject, quote=True)
		
		#~ generate NZB
		if(len(segs)):
			templatedata = ''
			with open('template.nzb', 'rt') as fp:
				templatedata = fp.read()
			fp.close()	
			#~ print 	templatedata
			s = string.Template(templatedata).substitute({'subject':cgi.escape(subject, quote=True), 'group':group, 'segments':segs})
			
			with open('_tmpgenerated.nzb', 'wt') as fp:
				fp.write(s)
			fp.close()
		
		#~ download NZB
		print ''
		print 'Download the tiniest and healthiest par2'
		if(DEBUG==0 ):
			subprocess.call(["rm","-rf","dst/_tmpgenerated"], stdout=subprocess.PIPE)
			subprocess.call(["nzbget","-c","nzbget.conf.commandline","_tmpgenerated.nzb"], stdout=subprocess.PIPE)
		 
	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

	def getinfofrompar(self):
		#~ outp['summary'] = fileinfo
		numblock={}

		for info in self.infodata['detail']:
			#~ if(info[2] == 4):
				#~ print info[5]
			if(info[2] == self.MSGTYPE_PAR2VOL and info[5] == self.STATUS_OK):
				par2idx = 	info[0].lower().find('.par2')
				
				#~ extract rootname
				npar = info[0][1:par2idx+5]
				npar_sep1 = info[0][1:par2idx].rfind(' ')
				npar_sep2 = info[0][1:par2idx].rfind('"')
				npar_sep_vol = info[0][1:par2idx].lower().rfind('.vol')
				minidx = max(npar_sep1,npar_sep2)
				self.infodata['rootfile'] = npar
				if(minidx != -1):
					self.infodata['rootfile'] = npar[minidx+1:npar_sep_vol]
				self.infodata['fullname'] = npar[minidx+1:par2idx+5]
				
				#~ extract block nums
				nblock_str1 = npar[npar_sep_vol:par2idx-1]
				nblock_str1_idx = nblock_str1.find('+')			
				if(nblock_str1_idx == -1):
					return {}
				numblock[self.infodata['fullname']] = int(nblock_str1[nblock_str1_idx+1:])
				info[6] = int(nblock_str1[nblock_str1_idx+1:])
		
		self.infodata['nblocks'] = 0
		for key in numblock:
			self.infodata['nblocks'] +=  numblock[key]

	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

	def getnzbinfo(self, data):
		h = HTMLParser.HTMLParser()                   

		soup = beautifulsoup.BeautifulSoup(data)
		fileno = soup.findAll('file')

		filesegs = []
		fileinfo  = {}
		fileinfo['pars'] = 0
		fileinfo['nfo'] = 0
		fileinfo['nofile'] = 0
		fileinfo['rar'] = 0
		fileinfo['nzb'] = 0
		fileinfo['sfv'] = 0
		fileinfo['postid'] = []
		
		allfiles={}
		
		rootfile = ''
		nbytes = 0
		
		for fno in fileno:	
			try:
				#~ print fno['subject']
				segs = fno.findAll('segments')		
				groups = fno.findAll('groups')
				fsggs = 0
				parfile = 0
				typefile = self.MSGTYPE_ARCHIVE
				
				#~ val =  re.search(r".r[0-9]{2,4}", fno['subject'], re.I)	
				val_sample =  re.search(r"[\.\-]sample", fno['subject'], re.I)	
				if(val_sample is not None):
					continue				
				par2idx = 	fno['subject'].lower().find('.par2')
				if ( par2idx != -1):
					typefile = self.MSGTYPE_PAR2IDX
					fileinfo['pars'] = fileinfo['pars'] + 1
					npar_vol =  re.search(r".vol[0-9]{1,4}", fno['subject'][1:par2idx+5], re.I)	
					if(npar_vol is not None):
						typefile = self.MSGTYPE_PAR2VOL
				if (fno['subject'].lower().find('.nfo') != -1):
					typefile = self.MSGTYPE_NFO
					fileinfo['nfo'] = fileinfo['nfo'] + 1
				if (fno['subject'].lower().find('.sfv') != -1):
					typefile = self.MSGTYPE_SFV
					fileinfo['sfv'] = fileinfo['sfv'] + 1
				if (fno['subject'].lower().find('.nzb') != -1):
					typefile = self.MSGTYPE_NZB
					fileinfo['nzb'] = fileinfo['nzb'] + 1
				
				if(typefile == 0):
					allfiles[h.unescape(fno['subject'])] = 1
					
				cur_group = []
				for g in groups:	
					g_groups = g.findAll('group')
					for g2 in g_groups:
						cur_group.append(''.join(g2.findAll(text=True)))

				for s in segs:	
					s_segs = s.findAll('segment')
					fsggs = fsggs + len(s_segs)
					postid = []
					for s2 in s_segs:
						nbytes += int (s2['bytes'])
						subject = h.unescape(fno['subject'])
						filesegs.append([ subject, 
										 int (s2['bytes']), 
										 typefile, 
										 h.unescape(''.join(s2.findAll(text=True))), 
										 cur_group, 
										 self.STATUS_INIT,
										 -2])

			except Exception as e:
				print "Error, could not parse NZB file " + str(e)
				sys.exit()

		allfiles_sorted=[]
		allfiles_sorted_clean=[]
		for key in allfiles:
			allfiles_sorted.append(key)
		allfiles_sorted = sorted(allfiles_sorted)	
		for s in allfiles_sorted:
			allfiles_sorted_clean.append(re.findall(r'\"(.+?)\"',s)[0])

		self.infodata={}
		self.infodata['summary'] = fileinfo
		self.infodata['detail'] = filesegs
		self.infodata['subject'] = allfiles_sorted
		self.infodata['filename'] = allfiles_sorted_clean
		#~ print self.infodata['filename']
		#~ return outp



	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

	def nzb_fix(self):
		if(self.par2funmatched):
			print 'Trying to fix the nzb'
			if(len(self.par2info['files']) != len(self.infodata['filename'])):
				print 'Found archive and par2 list do not match. Nothing to do here'	
				return 0
			
			print 'Found archives and par2 list match in number'
			#~ regenerate NZB
			
			#~ par2 will take care of reassiging filenames, saving fixed file
			count = 0
			for p in self.par2info['files']:
				self.data = self.data.replace(self.infodata['filename'][count], p)
				self.infodata['filename'][count] = p
				count += 1
			with open('fixed.nzb', 'wt') as fp:
				fp.write(self.data)
			fp.close()
			#~ replace broken segments			
			counti = 1
			for m in self.infodata['detail']:
				if(m[5] == self.STATUS_PAR2UNMATCHED):
					m[5] = self.STATUS_OK
					print counti
					counti = counti + 1
			
			#~ check health
			print ''
			print '********************************************'			
			print '********************************************'
			print 'THE FOLLOWING IS ABOUT THE AUTO-FIXED NZB'
			print 'this is based on educated guess'
			print 'use it as last resort'
			print '********************************************'
			print '********************************************'
			print ''

			nzbh.calculate_health(True)
							

	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

	def analyzefilelistpar(self):
		print 'Extracting info from par2'
		process = subprocess.Popen(['par2verify', 'dst/_tmpgenerated/*.par2'], stdout=subprocess.PIPE)
		out, err = process.communicate()
		bmsg = 'The block size used was '
		nidx = out.find(bmsg)
		nidx2 = out[nidx+len(bmsg):].find(' ')
		blocksize = int(out[nidx+len(bmsg):nidx2+nidx+len(bmsg)])
		if(nidx == -1 or nidx2 == -1):
			print 'FATAL: cannot find block size, par2 or download failed'
			return -1
		nidx = out.find('Target')
		listfiles=map(lambda x:x.lower(),re.findall(r'\"(.+?)\"',out[nidx:]))	
		
		self.par2info = {}
		self.par2info['pars'] = 0
		self.par2info['nfo'] = 0
		self.par2info['nofile'] = 0
		self.par2info['rar'] = 0
		self.par2info['nzb'] = 0
		self.par2info['sfv'] = 0
		self.par2info['postid'] = []
		self.par2info['files'] = []
		for lf in listfiles:
			typefile = self.MSGTYPE_ARCHIVE
			if(lf.lower().find('-sample') != -1):
				continue				
			if ( lf.lower().find('.par2') != -1):
				continue
			if (lf.lower().find('.nfo') != -1):
				typefile = self.MSGTYPE_NFO
				self.par2info['nfo'] = self.par2info['nfo'] + 1
			if (lf.lower().find('.sfv') != -1):
				typefile = self.MSGTYPE_SFV
				self.par2info['sfv'] = self.par2info['sfv'] + 1
			if (lf.lower().find('.nzb') != -1):
				typefile = self.MSGTYPE_NZB
				self.par2info['nzb'] = self.par2info['nzb'] + 1
			#~ self.par2info['files'].append([lf, typefile] )	
			if(typefile == self.MSGTYPE_ARCHIVE):
				self.par2info['files'].append(lf)	
		
		#~ print self.par2info['files']
		#~ chk existency
		self.par2funmatched = len(self.par2info['files'])
		for p in self.par2info['files']:
			for s in self.infodata['filename']:
				if(s == p):
					self.par2funmatched -= 1
					break

		if(len(listfiles) == 0):
			print 'FATAL: cannot find available file list from par2'
			return -1
				
		#~ declare them invalid
		for info in self.infodata['detail']:
			if(info[5] == self.STATUS_OK):
				isfound = False
				for l in listfiles:
					if(info[0].lower().find(l) != -1):
						isfound = True
						break
				if(isfound == False):
					info[5]	= self.STATUS_PAR2UNMATCHED
			
		return blocksize	
		

	#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 


	def calculate_health(self, mode_recheck=False ):
		overall_count = 0
		missing_count = 0
		overall_count_articles = 0
		missing_count_articles = 0
		
		#~ par ecc
		if(DEBUG == 0):
			for m in self.infodata['detail']:
				if( (m[2] == self.MSGTYPE_PAR2VOL or m[2] == self.MSGTYPE_PAR2IDX)   and m[5] != self.STATUS_OK):
					#~ broken par remove all entries related to this file, -10 removal marking
					for m1 in self.infodata['detail']:
						if(m[0] == m1[0] ):
							m1[5] = -1	
		if(DEBUG):
			for m in self.infodata['detail']:
				if( (m[2] == self.MSGTYPE_PAR2VOL or m[2] == self.MSGTYPE_PAR2IDX)   and m[5] != self.STATUS_OK):
					for m1 in self.infodata['detail']:
						if(m[0] == m1[0] ):
							m1[5] = 1	

		#~ compute block avail
		parinfo = self.getinfofrompar()
		#~ download smallest par pack, anaylize with par2 the block size 
		if(mode_recheck == False):
			self.getsmallest_healthy_par()
		self.blocksize = self.analyzefilelistpar()

		#~ archive
		overall_count = 0
		missing_count = 0
		par2miss = 0
		goodfiles_count = 0
		for m in self.infodata['detail']:
			if(m[2] == self.MSGTYPE_ARCHIVE):
				overall_count += m[1]
				goodfiles_count += 1
				if( m[5] == self.STATUS_PAR2UNMATCHED ):
					par2miss  += m[1]
				if( m[5] == self.STATUS_ERROR or m[5] == self.STATUS_MISS or m[5] == self.STATUS_INIT):
					missing_count += m[1]
		
		availblocks = self.infodata['nblocks']
		totblocks = float(overall_count) / float(self.blocksize)
		missblocks = float(missing_count) / float(self.blocksize)
		par2missblocks = float(par2miss) / float(self.blocksize)
		
		print ''
		#~ print 'Tot (yenc compressed): ' + str(overall_count) + ' bytes Miss (yenc compressed): ' + str(missing_count) + ' bytes'
		print 'Analysis (yenc compressed)'
		print '=========================='
		print 'Total in bytes: ' + str(overall_count)
		print 'Miss. in bytes: ' + str(missing_count)

		if (missblocks > 0 and missblocks < 1):
			missblocks = 1
		if(self.blocksize != -1):
			#~ if (par2miss > 0):
				#~ print 'Broken NZB? Recovery file segments not listed in par2: ' + str(par2miss) + '/' + str(goodfiles_count)
			
			#~ these are conservative estimates
			print 'Blocksize non-yenc compressed: ' + str(self.blocksize)
			print 'Totblocks: %.2f' % totblocks 
			print '> Missblocks: %.2f' %  missblocks 
			if(self.par2funmatched):
				print '> There are ' + str(self.par2funmatched) + '/'+ str(len(self.par2info['files'])) +' files not found in par2'
			if(par2missblocks):	
				print '> Unrepairable blocks (non in par2): %.2f' %  par2missblocks
				
			print '> Availblocks: %.2f' %  availblocks
			print ''
			print 'Results'
			print '=========================='
			availblocks = availblocks - par2missblocks

			if(missblocks == 0):
				print 'Perfect data'
			else:
				
				if(availblocks > missblocks-BLOCKAPPROX and availblocks <= missblocks):
					print 'This *might* be fixable, this script uses a conservative estimate due to yenc compression'
				elif(availblocks > missblocks):
					print 'Ok or fixable through PAR2'
				else:	
					print 'This is broken'		
		else:
			print 'PAR2 info not available'
			if(overall_count != missing_count):
				print 'This is broken'		
			else:	
				print 'Ok. All messages are on the server'
		

#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 
#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

def completion_monitor(outp, connmax):
	while (completion_counter_allout != connmax-1 ):
		time.sleep(1)
		#~ print '\r[{0}] {1}%'.format('#'*(completion_counter/len(outp['detail'])), len(outp['detail']))
		print "\r"+str(completion_counter) + '/' +str(len(outp['detail'])),
		sys.stdout.flush()

def printUsage():
	print "Usage: python nzb_checker.py  --nzb=thisismynzb.nzb --server=newszilla6.xs4all.nl --user=newsservername --pass=newsserverpassword [--connections=4]  [--debug=1]"

#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 
#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

def signal_handler(signal, frame):
        print 'You pressed Ctrl+C!'
        sys.exit(0)
        	
	
#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 
#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 
	
print '++++++++++++++++++++++++++++++++++++++++++++'
print '(Almost) Accurate NZB automated verification'
print 'from 0byte'
print '++++++++++++++++++++++++++++++++++++++++++++'
print ''
conf={}
conf['connections'] = 19
conf['host'] = ''
conf['user'] = ''
conf['pass'] = ''

opts, args = getopt.getopt(sys.argv[1:], "n:s:u:p:t:dS",['nzb=','server=','user=','pass=','connections=','debug='])

for opt, arg in opts:
	if (opt in ('-n', '--nzb')):
		nzbfilename1 = arg
	elif opt in ('-s', '--server'):
		conf['host'] = arg
	elif opt in ('-u', '--user'):
		conf['user'] = arg
	elif opt in ('-p', '--pass'):
		conf['pass'] = arg
	elif opt in ('-c', '--connections'):
		conf['connections'] = int(arg)
	elif opt in ('-d', '--debug'):
		if int(arg)>0:
			debug = True

signal.signal(signal.SIGINT, signal_handler)

if(len(conf['host'])==0 or len(conf['user'])==0 or len(conf['pass'])==0):
	printUsage()
	exit(1)			
if(len(nzbfilename1)==0):
	print 'missing nzb input' 
	exit(1)			

print 'Connecting with the server ('+str(conf['connections'])+' connections)'

print 'Parsing NZB'
nzbh = HealthChecker(open(nzbfilename1).read())
nnt = []
tthr = []

print 'Connecting server'
if(DEBUG == 0):
	for i in xrange(conf['connections']):
		nnt.append(TelnetConnection(conf,i))
	for i in xrange(conf['connections']):
		tthr.append( threading.Thread(target=nnt[i].init_and_stat, args=([nzbh.infodata]) ) )
	tthr.append( threading.Thread(target=completion_monitor, args=(nzbh.infodata, conf['connections']) ) )	
	for t in tthr:
		t.start()
	for t in tthr:
		t.join()

nzbh.calculate_health()
nzbh.nzb_fix()
