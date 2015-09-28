import signal
import sys
import nfc
import time
import os
import threading
import multiprocessing as MP
import smtplib
import RPi.GPIO as GPIO

SIGNAL_PIN = 23
VERSION = 0.55

print """
RPi NFC Security v%d
Copyright Tyler Dinsmoor 2015

Licensed under GNU GPL v3 or greater.

"""%VERSION

try:
    print("Disabling interfering services")
    # pcscd steals the interface for some NFC readers, if installed.
    os.system('sudo service pcscd stop')
except Exception as err:
    print err

try:
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(SIGNAL_PIN,GPIO.IN)
    # pin setup is a pull-up resistor setup.
    '''
POSTITIVE PIN +_______________DOOR SWITCH_
NEGATIVE PIN  -__10kOhm_______DOOR SWITCH_|
DETECTION PIN O__________|
    '''
    print("Set up detection on GPIO pin %d"%SIGNAL_PIN)
except Exception as err:
    print err
    print("Cannot set GPIO. Check root?")
    exit()

try:
    # This is to make sure that the nfcpy library can grab ahold of the reader.
    clf = nfc.ContactlessFrontend('usb')
    print("Set up USB NFC interface")
except:
    print ("Could not set up USB NFC interface. Does another process have custody?")
    exit()

def signal_exit(signal, frame): exit()

def get_f_f_dic(fi):
    # for importing the users file
    d = {}
    with open(fi) as f:
        for line in f:
            if not line.startswith("#"):
                (key, val) = line.strip().split('=')
                d[key] = val
    return d

# timestamp
def cur_time(): return time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())


def check_door():
    # quick T/F if SIGNAL_PIN has high/low resistance
    if GPIO.input(SIGNAL_PIN):
        return False
    return True

def init_logfile():
    # had issues with it not writing after including multiprocessing, so
    # possible fix.
    fi = open('access_log','w')
    fi.write("\nStarting RPi NFC Security v%d @ %s\n"%(VERSION,cur_time()))
    fi.close()

#Helps catch ^C if waiting for scan
signal.signal(signal.SIGINT, signal_exit)
USERS = get_f_f_dic('users')
init_logfile()
LOGFILE = open('access_log','a')


class DoorMonitor:
    def __init__(self):
        while True:
            if check_door():
                # acts as a backup incase the noscan_proc fails to
                # terminate
                self.has_scanned = False
                open_time = cur_time()
                LOGFILE.write("\nDOOR OPEN: %s" %open_time)
                print("\nDOOR OPEN: %s" %open_time)
                self.wait_for_connect()
            else: #Waits here until the door is opened
                time.sleep(1)
                
    def wait_for_connect(self):
        # Creates forked process after door is opened, so that after
        # ten seconds, it'll send an alert to the user.
        self.noscan_proc = MP.Process(target=self.log_noscan)
        self.noscan_proc.start()
        print('Listening for Card')
        def connect():
            # Ok lets wait here on the main thread
            # for a bit until a card gets in touch
            clf.connect(rdwr={'on-connect': self.connected})
            print('Conected to Card')
        connect()
        # wait so we don't have it send a bunch of messages
        time.sleep(10)
        
    def connected(self, tag):
        # once we scan, we don't want to send an alert for not
        # scanning!
        self.noscan_proc.terminate()
        # just gets bytearray -> hex
        tagid = "".join('{:02x}'.format(x) for x in tag._nfcid)
        self.has_scanned = True
        # Lets put it in the book!
        self.log_scan(tagid)
        return False

    def log_scan(self, tagid):
        try:
            # Is the tag ID in our users file?
            user = USERS[tagid]
        except KeyError:
            # No? Ok, lets send the tag ID, in case the user probably just
            # wants to make an entry in the users file
            user = "INVALID USER %s" %tagid
        LOGFILE.write((user +" " + cur_time()))
        # cool, lets tell the user now
        self.send_alert(cur_time(), user=user)
        time.sleep(60) # one minute to come back in

    def log_noscan(self):
        time.sleep(10) # since it's in own process, ok to wait here.
        # It lets us wait for self.has_scanned to be set, because sometimes
        # the noscan_proc fails to terminate in time.
        if self.has_scanned:
            return # we're done here
        print "DOOR OPEN; USER UNKNOWN",cur_time()
        # Let's tell the user
        self.send_alert(cur_time())
        LOGFILE.write("\nDOOR OPEN; USER UNKNOWN " + cur_time())
        time.sleep(60) # one min timeout, no sense in spamming
    
    def send_alert(self, log_time, user="UNKNOWN"):
        # can send normal or emergency alerts
        sender = "my mail identity" # using an external SMTP server here
        receivers = ['verizonphonenumber@vtext.com',
                    'regularemail@airmail.cc',
                    'sprintdoesntlikeityet@pm.sprint.com']
                    
        message = "%s @ %s w/ Open? %s" %(user, log_time, str(check_door()))
    
        try:
            # create a SMTP object
            server = smtplib.SMTP("mymail.server", 587)
            # tell SMTPlib that it'll use STARTTLS for security
            server.starttls()
            # do plain login
            server.login('myusername','mypassword')
            # send the message to each of the recivers
            for rec in receivers:
                server.sendmail(sender, rec, message)
                print("Successfully sent alert to %s"%str(rec))
                LOGFILE.write("\nSent alert to %s" %str(rec))
            # lets not leave the interface open
            server.quit()
        except smtplib.SMTPException as err:
            # You will get an error unless you change the mail settings
            print("Unable to send alert")
            LOGFILE.write('\n Unable to send alert: %s'%err)
            print err
        
if __name__ == "__main__":
    DoorMonitor()
