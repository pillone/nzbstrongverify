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

MAXREPEAT = 3
TIMEOUT = 5
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

def getsmallest_healthy_par(infodata):
	
	cursmallest = len(infodata['detail'])
	smallest_par_segment = []
	segmentstr = '<segment bytes="$bytes" number="$num">$mid</segment>'
	count = 1
	subject = ''
	group = ''
	#~ get smallest vol
	for info in infodata['detail']:
		if(info[6] < cursmallest):
			if((info[2] == 4 or info[2] == 1) and info[5] == 1 ):
				cursmallest = info[6]

	#~ get all segments
	segs = ''
	for info in infodata['detail']:
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
	
	#~ print cursmallest
	
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
	subprocess.call(["rm","-rf","dst/_tmpgenerated"], stdout=subprocess.PIPE)
	subprocess.call(["nzbget","-c","nzbget.conf.commandline","_tmpgenerated.nzb"], stdout=subprocess.PIPE)
	
	process = subprocess.Popen(['par2verify', 'dst/_tmpgenerated/*.par2'], stdout=subprocess.PIPE)
	out, err = process.communicate()
	bmsg = 'The block size used was '
	nidx = out.find(bmsg)
	nidx2 = out[nidx+len(bmsg):].find(' ')
	if(nidx == -1 or nidx2 == -1):
		print 'FATAL: cannot find block size, par2 or download failed'
		return -1

	blocksize = int(out[nidx+len(bmsg):nidx2+nidx+len(bmsg)])

	return blocksize
#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

def getinfofrompar(infodata):
	#~ outp['summary'] = fileinfo
	output={}
	numblock={}

	for info in infodata['detail']:
		#~ if(info[2] == 4):
			#~ print info[5]
		if(info[2] == 4 and info[5] == 1):
			par2idx = 	info[0].find('.par2')
			
			#~ extract rootname
			npar = info[0][1:par2idx+5]
			npar_sep1 = info[0][1:par2idx].rfind(' ')
			npar_sep2 = info[0][1:par2idx].rfind('"')
			npar_sep_vol = info[0][1:par2idx].rfind('.vol')
			minidx = max(npar_sep1,npar_sep2)
			output['rootfile'] = npar
			if(minidx != -1):
				output['rootfile'] = npar[minidx+1:npar_sep_vol]
			output['fullname'] = npar[minidx+1:par2idx+5]
			
			#~ extract block nums
			nblock_str1 = npar[npar_sep_vol:par2idx-1]
			nblock_str1_idx = nblock_str1.find('+')			
			if(nblock_str1_idx == -1):
				return {}
			numblock[output['fullname']] = int(nblock_str1[nblock_str1_idx+1:])
			info[6] = int(nblock_str1[nblock_str1_idx+1:])
	
	#~ output['nblocks'] = numblock
	output['nblocks'] = 0
	for key in numblock:
		output['nblocks'] +=  numblock[key]

	return output		

#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

def getnzbinfo(data):
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
	rootfile = ''
	nbytes = 0
	for fno in fileno:	
		try:
			#~ print fno['subject']
			segs = fno.findAll('segments')		
			groups = fno.findAll('groups')
			fsggs = 0
			parfile = 0
			typefile = 0
			
			#~ val =  re.search(r".r[0-9]{2,4}", fno['subject'], re.I)	
			val_sample =  re.search(r"[\.\-]sample", fno['subject'], re.I)	
			if(val_sample is not None):
				continue				
			par2idx = 	fno['subject'].find('.par2')
			if ( par2idx != -1):
				typefile = 1
				fileinfo['pars'] = fileinfo['pars'] + 1
				npar_vol =  re.search(r".vol[0-9]{1,4}", fno['subject'][1:par2idx+5], re.I)	
				if(npar_vol is not None):
					typefile = 4
			if (fno['subject'].find('.nfo') != -1):
				typefile = 2
				fileinfo['nfo'] = fileinfo['nfo'] + 1
			if (fno['subject'].find('.sfv') != -1):
				typefile = 3
				fileinfo['sfv'] = fileinfo['sfv'] + 1
			if (fno['subject'].find('.nzb') != -1):
				typefile = 5
				print fno['subject']
				fileinfo['nzb'] = fileinfo['nzb'] + 1
			
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
					filesegs.append([ h.unescape(fno['subject']), int (s2['bytes']), typefile, h.unescape(''.join(s2.findAll(text=True))), cur_group, -3, -2])

		except Exception as e:
			print "Error, could not parse NZB file " + str(e)
			sys.exit()

	outp={}
	outp['summary'] = fileinfo
	outp['detail'] = filesegs
	return outp


#~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 


def calculate_health(msg):
	overall_count = 0
	missing_count = 0
	overall_count_articles = 0
	missing_count_articles = 0
	
	#~ par ecc
	

	for m in msg['detail']:
		if( (m[2] == 4 or m[2] == 1)   and m[5] != 1 ):
			#~ broken par remove all entries related to this file, -10 removal marking
			for m1 in msg['detail']:
				if(m[0] == m1[0] ):
					m1[5] = -1	

	'''
	#~ FAKE
	#~ ===================
	for m in msg['detail']:
		if((m[2] == 4  or m[2] == 1)and m[5] != 1 ):
			#~ broken par remove all entries related to this file, -10 removal marking
			for m1 in msg['detail']:
				if(m[0] == m1[0] ):
					m1[5] = 1	
	#~ ===================
	'''
	#~ compute block avail
	parinfo = getinfofrompar(msg)
	#~ download smallest par pack, anaylize with par2 the block size 
	bsze = getsmallest_healthy_par(msg)
	availblocks = parinfo['nblocks']

	#~ archive
	overall_count = 0
	missing_count = 0
	for m in msg['detail']:
		if(m[2] == 0 ):
			overall_count += m[1]
			if( m[5] != 1 ):
				missing_count += m[1]

				
	#~ "%.2f" % a
	totblocks = overall_count / bsze
	missblocks = missing_count / bsze
	
	print 'Tot: ' + str(overall_count) + ' Miss: ' + str(missing_count)
	if(bsze != -1):
		print 'Blocksize (reported by par2): ' + str(bsze)
		print 'Totblocks: %.2f' % totblocks + ' Missblocks: %.2f' %  missblocks + ' Availblocks: %.2f' %  availblocks

		if(missblocks == 0):
			print 'Perfect data'
		else:
			if(availblocks > missblocks):
				print 'Ok or fixable through PAR2'
			else:	
				print 'This is broken'		
	else:
		print 'PAR2 info not available'
	
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
print '++++++++++++++++++++++++++++++++++++'
print 'Accurate NZB automated verification'
print 'from 0byte'
print '++++++++++++++++++++++++++++++++++++'

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
	elif opt in ('-t', '--threads'):
		conf['connections'] = int(arg)
	elif opt in ('-d', '--debug'):
		if int(arg)>0:
			debug = True

#~ print conf 

if(len(conf['host'])==0 or len(conf['user'])==0 or len(conf['pass'])==0):
	printUsage()
	exit(1)			
if(len(nzbfilename1)==0):
	print 'missing nzb input' 
	exit(1)			

# TODO: Listen to other signals
signal.signal(signal.SIGINT, signal_handler)

data1 = open(nzbfilename1).read()
outp = getnzbinfo(data1)
nnt = []
tthr = []
for i in xrange(conf['connections']):
	nnt.append(TelnetConnection(conf,i))
for i in xrange(conf['connections']):
	tthr.append( threading.Thread(target=nnt[i].init_and_stat, args=([outp]) ) )
tthr.append( threading.Thread(target=completion_monitor, args=(outp, conf['connections']) ) )	
for t in tthr:
	t.start()
for t in tthr:
	t.join()

msg = calculate_health(outp)



