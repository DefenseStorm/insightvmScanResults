#!/usr/bin/env python3

import sys,os,getopt
import traceback
import io
import os
import fcntl
import json
import time
import csv
import requests
from random import randrange
from datetime import datetime
import zipfile
from io import StringIO

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):

    JSON_field_mappings = {
            'Asset IP Address':'source_ip',
            'Service Port':'source_port',
            'Vulnerability Test Result Code':'result',
            'Severity Level':'severity',
            'Vulnerability Title':'message',
            }

    def get_scan(self, report_id):

        URL = self.scanner + '/api/3/reports/' + report_id + '/history/latest/output/'
        try:
            r = requests.get(url = URL, auth=(self.user, self.password), verify = False)
        except Exception as e:
            self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
            self.ds.logger.error("Exception {0}".format(str(e)))
            return None
        if not r or r.status_code != 200:
            self.ds.logger.warning(
                    "Received unexpected " + str(r) + " response from InsightVM Server {0}.".format(
                    URL))
            return None
        return r.text


    def send_scan_to_grid(self, report_id, results):
        # Asset IP Address,Service Port,Vulnerability Test Result Code,Vulnerability ID,Vulnerability CVE IDs,Vulnerability Severity Level,Vulnerability Title
        f = StringIO(results)
        dicted = csv.DictReader(f)
        vulns = list(dicted)
        for entry in vulns:
            asset = {}
            for key in entry:
                if entry[key] == "":
                    entry[key] = "None"
            entry['scanner'] = self.scanner
            #entry['timestamp'] = scan_time
            self.ds.writeJSONEvent(entry, JSON_field_mappings = self.JSON_field_mappings, flatten = False)

    def insightvm_main(self): 

        # Get insightvm Config info
        self.upload_scans_to_grid = False

        try:
            self.user = self.ds.config_get('insightvm', 'user')
            self.password = self.ds.config_get('insightvm', 'password')
            self.scanner = self.ds.config_get('insightvm', 'scanner')
            self.state_dir = self.ds.config_get('insightvm', 'state_dir')
            self.report_id = self.ds.config_get('insightvm', 'report_id')

            self.days_ago = 1
            self.last_run = self.ds.get_state(self.state_dir)

            self.time_format = "%Y-%m-%d %H:%M:%S"

            current_time = time.time()

            if self.last_run == None:
                self.ds.logger.info("No previous state.  Collecting logs for last " + str(self.days_ago) + " days")
                #self.last_run = (datetime.utcfromtimestamp((current_time - ( 60 * 60 * 24 * int(self.days_ago))))).strftime(self.time_format)
                self.last_run = current_time - ( 60 * 60 * 24 * int(self.days_ago))
            self.current_run = current_time
        except Exception as e:
                self.ds.logger.error("Failed to get required configurations")
                self.ds.logger.error("Exception {0}".format(str(e)))
                self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))

        try:
            results = self.get_scan(self.report_id)
        except Exception as e:
            self.ds.logger.error("Failed to get scan %s" %self.report_id)
            self.ds.logger.error("Exception {0}".format(str(e)))
            self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
    
        self.send_scan_to_grid(report_id = self.report_id, results = results)

        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.logger.info("Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('insightvm', 'pid_file')
            fp = io.open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.logger.error("An instance of this integration is already running")
                # another instance is running
                sys.exit(0)
            self.insightvm_main()
        except Exception as e:
            self.ds.logger.error("Exception {0}".format(str(e)))
            self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
            return
    
    def usage(self):
        print (os.path.basename(__file__))
        print ('\n  No Options: Run a normal cycle\n')
        print ('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print ('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print ('        in the current directory\n')
        print ('  -l    Log to stdout instead of syslog Local6\n')
        print ('  -a    Generate a .csv file that can be used for Asset Import in Grid\n')
        print ('  -k    Keep scan files (.insightvm and .csv files)\n')
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.conf_file = None
        self.conn_url = None
        self.gen_assets_file = False
        self.keep_files = False
    
        try:
            opts, args = getopt.getopt(argv,"htlkac:")
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
            elif opt in ("-c"):
                self.conf_file = arg
            elif opt in ("-a"):
                self.gen_assets_file = True
            elif opt in ("-k"):
                self.keep_files = True
    
        try:
            self.ds = DefenseStorm('insightvmScanResults', testing=self.testing, send_syslog = self.send_syslog, config_file = self.conf_file)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.logger.error('ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
