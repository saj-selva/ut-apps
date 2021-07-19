#!/usr/bin/python3

'''
  Simple python script to collect data from testbed 

  Apr 2021, Sajiv Selvaraj

  Copyright (c) 2020-2021 by Cisco Systems, Inc.
  All rights reserved.
'''
import os, subprocess
import sys
import argparse
import logging
import re
import time
import os.path
import getpass
import socket
from unicon import Connection
import csv
from io import StringIO
import threading
from pathlib import Path
from prometheus_client import start_http_server,Counter,Gauge

class cli_command:
        
        def __init__(self, _dev, _dict, _name, _cmd, cumulative=False, xml=False):

            self.dev = _dev
            self.parse_dict = _dict
            self.cmd = _cmd
            self.is_cumlative = cumulative
            self.is_xml = xml
            self.last_store = None
            self.data_list = []
            self.stats = Gauge(_name, "descr-"+_name, ['counter'])

        def run(self):

            if self.is_xml:
                execute_remote_command_cli(self.dev, "req platform software shell session output format xml")

            data = execute_remote_command_cli(self.dev, self.cmd)

            if self.is_xml:
                execute_remote_command_cli(self.dev, "req platform software shell session output format text")

            #start thread after data is fetched from server
            
            t = threading.Thread(target=self.process_cmd_output, name="data_processor", args=(data,))
            t.start()

        def process_cmd_output(self, data): 

            parse_val = []
            val = []
            for key,value in self.parse_dict.items():
                parse_val.append(re.search(value, data).group(1))

            if self.is_cumlative:
                if not self.last_store:
                    self.last_store = list(parse_val)
                    return
                for i,j in zip(parse_val, self.last_store):
                    val.append(int(i)-int(j))
                self.last_store = list(parse_val)
            else: 
                if not self.last_store:
                    self.last_store = list(parse_val)
                val = parse_val

            self.promethus_data_store(list(self.parse_dict.keys()), val)

        def promethus_data_store(self, _label, data):
            for data_val,label_val in zip(data,_label):
                self.stats.labels(label_val).set(int(data_val))

#
# Command line argument parser
#
def parse_command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument("testbed", type=str, 
                        help="IP address of testbed CLI console")
    parser.add_argument("hostname", type=str, 
                        help="Host name of the testbed")
    parser.add_argument("-u","--username", type=str, default='admin',
                        help="login username")
    parser.add_argument("-ps","--passwd", type=str, default='Wlc!1234',
                        help="login password")
    parser.add_argument("-d","--csv_dir", type=str, default='$HOME',
                        help="directory to store the csv files. Default is home directory")

    parser.add_argument("-g","--gigintf", type=str, default='g3',
                        help="eth interface to get the rate. eg g1 g2 g3. Default is g3")
    parser.add_argument("-p", "--port", type=int, default=23,
                        help="Port used for the telnet session")

    return parser.parse_args()

#
# logger initialization 
# Info level and above logs are written to the console. 
# Rest are written to /tmp/debug.txt file 
#
def config_logging(): 
    # set up logging to file - see previous section for more details
    logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
            datefmt='%m-%d %H:%M',
            filename='/tmp/debug.log',
            filemode='wb')
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler(StringIO())
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger().addHandler(console)
    return logging

#
# Establish a telnet session with the target
#
def open_telnet_conn_cli(ip, timeout):
    server = 'telnet '+ ip + ' ' + str(args.port) 
    dev = Connection(hostname=args.hostname,
        start=[server],
        credentials={'default': {'username': args.username, 'password': args.passwd}},
        os='ios')
    dev.connect()
    return dev

#
# Split the telnet session data to files 
# Dump each line to the debug log file
#
def print_command_data(command_data):
    data=command_data.splitlines()
    for line in data:
        logger.debug("\t\t"+line)

#
# Execute a command on the target
#
def execute_remote_command_cli(t, command):
    command_data = t.execute(command)
    return command_data

logger = config_logging()
args = parse_command_line()

'''
    parser dict for all cli commands to be used
'''

pfcp_dict_xml = {
        'sess_est_req_rcvd': ".*<sess_est_req_rcvd>([0-9]+).*",
        'sess_est_rsp_success_sent': ".*<sess_est_rsp_success_sent>([0-9]+)<.*",
        'sess_est_rsp_failure_sent': ".*<sess_est_rsp_failure_sent>([0-9]+)<.*",
        'sess_mod_req_rcvd': ".*<sess_mod_req_rcvd>([0-9]+)<.*",
        'sess_mod_rsp_success_sent': ".*<sess_mod_rsp_success_sent>([0-9]+)<.*",
        'sess_mod_rsp_failure_sent': ".*<sess_mod_rsp_failure_sent>([0-9]+)<.*",
        'sess_del_req_rcvd': ".*<sess_del_req_rcvd>([0-9]+)<.*",
        'sess_del_rsp_success_sent': ".*<sess_del_rsp_success_sent>([0-9]+)<.*",
        'sess_del_rsp_failure_sent': ".*<sess_del_rsp_failure_sent>([0-9]+)<.*",
        'sess_del_req_sent': ".*<sess_del_req_sent>([0-9]+)<.*",
        'sess_del_rsp_success_rcvd': ".*<sess_del_rsp_success_rcvd>([0-9]+)<.*",
        'sess_del_rsp_failure_rcvd': ".*<sess_del_rsp_failure_rcvd>([0-9]+)<.*",
        'sess_report_req_sent': ".*<sess_report_req_sent>([0-9]+)<.*",
        'sess_report_success_rsp_rcvd': ".*<sess_report_success_rsp_rcvd>([0-9]+)<.*",
        'sess_report_failure_rsp_rcvd': ".*<sess_report_failure_rsp_rcvd>([0-9]+)<.*",
        'flow_create_req_sent': ".*<flow_create_req_sent>([0-9]+)<.*",
        'flow_create_success_rsp_rcvd': ".*<flow_create_success_rsp_rcvd>([0-9]+)<.*",
        'flow_create_failure_rsp_rcvd': ".*<flow_create_failure_rsp_rcvd>([0-9]+)<.*",
        'flow_delete_req_sent': ".*<flow_delete_req_sent>([0-9]+)<.*",
        'flow_delete_success_rsp_rcvd': ".*<flow_delete_success_rsp_rcvd>([0-9]+)<.*",
        'flow_delete_failure_rsp_rcvd': ".*<flow_delete_failure_rsp_rcvd>([0-9]+)<.*",
        'flow_tuple_add_req_sent': ".*<flow_tuple_add_req_sent>([0-9]+)<.*",
        'flow_tuple_add_success_rsp_rcvd': ".*<flow_tuple_add_success_rsp_rcvd>([0-9]+)<.*",
        'flow_tuple_add_failure_rsp_rcvd': ".*<flow_tuple_add_failure_rsp_rcvd>([0-9]+)<.*",
        'flow_tuple_del_req_sent': ".*<flow_tuple_del_req_sent>([0-9]+)<.*",
        'flow_tuple_del_success_rsp_rcvd': ".*<flow_tuple_del_success_rsp_rcvd>([0-9]+)<.*",
        'flow_tuple_del_failure_rsp_rcvd': ".*<flow_tuple_del_failure_rsp_rcvd>([0-9]+)<.*",
        'dl_data_report_sent': ".*<dl_data_report_sent>([0-9]+)<.*",
        'err_ind_report_sent': ".*<err_ind_report_sent>([0-9]+)<.*",
        'up_inact_report_sent': ".*<up_inact_report_sent>([0-9]+)<.*",
        'drop_buffered_report_resp_rcvd': ".*<drop_buffered_report_resp_rcvd>([0-9]+)<.*",
        'drop_buffered_mod_req_rvd': ".*<drop_buffered_mod_req_rvd>([0-9]+)<.*",
        'config_update_del_req_sent': ".*<config_update_del_req_sent>([0-9]+)<.*",
        'dpath_nack_del_req_sent': ".*<dpath_nack_del_req_sent>([0-9]+)<.*",
        'end_marker_send_fail_del_req_sent': ".*<end_marker_send_fail_del_req_sent>([0-9]+)<.*",
}

interface_rate = {
        'input_bit_rate': ".*input rate ([0-9]+) bits.*", 
        'input_pkt_rate': ".*input rate .*, ([0-9]+) packets.*",
        'output_bit_rate': ".*output rate ([0-9]+) bits.*", 
        'output_pkt_rate': ".*output rate .*, ([0-9]+) packets.*",
}

cpu = {
        'CPU': "CPU utilization.*one minute[\s:]+([0-9]+).*", 
        'Core0_CPU': "Core 0.*one minute[\s:]+([0-9]+).*", 
        'Core1_CPU': "Core 1.*one minute[\s:]+([0-9]+).*", 
        'Core2_CPU': "Core 2.*one minute[\s:]+([0-9]+).*", 
        'Core3_CPU': "Core 3.*one minute[\s:]+([0-9]+).*", 
        'UEMGR': ".*\%[\s]+([0-9]+)\%.*uemgr_0", 
        'UCODE_pkt_PPE0': ".*\%[\s]+([0-9]+)\%.*ucode_pkt_PPE0", 
        'FMAN_FP': ".*\%[\s]+([0-9]+)\%.*fman_fp_image", 
        'FMAN_RP': ".*\%[\s]+([0-9]+)\%.*fman_rp", 
        'CPP_CP_SRV': ".*\%[\s]+([0-9]+)\%.*cpp_cp_svr", 
        'CPP_SP_SRV': ".*\%[\s]+([0-9]+)\%.*cpp_sp_svr", 
}

mem = {
        'Free': ".*total,[\s]+([0-9]+)\.[0-9].*free,.*", 
        'Used': ".*free,[\s]+([0-9]+)\.[0-9].*used,.*", 
        'Buffer': ".*used,[\s]+([0-9]+)\.[0-9].*buff.*", 
}

t = open_telnet_conn_cli(args.testbed, 10)

cmds=[]
cmds.append(cli_command(t, pfcp_dict_xml, "PFCP_stats_total", 
                        "show packet-core stats session management | sec pfcp", 
                        cumulative=True, xml=True))

cmds.append(cli_command(t, interface_rate, "Interface_rate_stats", 
                        "sh int " + args.gigintf + " | i rate")) 

cmds.append(cli_command(t, cpu, "CPU_stats", 
                        "show processes cpu platform sorted | i CPU utilization|uemgr|cpp|ucode|fman")) 

cmds.append(cli_command(t, mem, "Memory_stats", 
                        "show platform software process slot chassis active R0 monitor | in Mem")) 

start_http_server(8000)

while (True): 
    for cmd in cmds:
        cmd.run()
    time.sleep(60)


