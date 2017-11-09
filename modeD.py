'''
Author - Vishvajeet Subhash Patil
The simulation of Heartbleed attack
'''
import subprocess
def init():
	print "Starting Apache Server for Simulation."
	subprocess.call(['sudo', 'https_proxy=','/home/segnate/dev/openssl/httpd2.4.25_1/bin/httpd'])
	print "Launched."
	print "Launching heartbleed monitor script."