import os
import sys
import signal
import time
import subprocess as sub
import threading

class RunCmd(threading.Thread):
    def __init__(self, cmd, timeout):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.timeout = timeout

    def run(self):
        self.p = sub.Popen(self.cmd)
        self.p.wait()

    def Run(self):
        self.start()
        self.join(self.timeout)

        if self.is_alive():
            self.p.terminate()      #use self.p.kill() if process needs a kill -9
            self.join()

def signal_handler(signal, frame):
        print('Bye')
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

start = time.time()

print "Analysing " + sys.argv[1]
try:
	cmd = "python dftest.py " + sys.argv[1] 
	RunCmd(cmd.split(' '), 60*60).Run() #1h!
	
	end = time.time()
except:
	pass

print "\t\tDone in " + str(end - start) + "s"
