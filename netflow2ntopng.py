import sys
import time, datetime
import logging, logging.handlers, getopt

import socket, struct
from struct import *
from socket import inet_ntoa

# update ntopng stats every 1s
import threading

# talk to ntopng
import zmq
import json

#
# packet information variables
#
packet_header_size = 24
flow_record_size = 48

#
# default settings
#

log_level="WARNING"

#ntop reported interface level
# TODO this should be per sensor?
ntop_iface_name = "w00t"

# probe address reported to ntop (this is our address)
ntop_probe_addr = "127.0.0.1"

# bind address for our ZMQ server (ntopng probe mode)
zmq_server = "tcp://*:5555"

# netflow v5 info
netflow_v5_port = 2055
netflow_v5_addr = '0.0.0.0'


def halp():
	print("""
NetflowV5 to NTOPNG reporter/converter/hack
DISCLAIMER: this is not stable, was thrown together in one day, use only for testing
Please use nProbe for production environments where you actually care about the metrics

This receives netflow V5 packets( from rflow/fprobe/etc) on port 2055(default)
and reports them via ZMQ(ZeroMQ) to NTOPNG.
(ntopng should be started with option -i '<our zmq-bind-addr>', without 'c' suffix)

Options:
 -h  --help                         Show this help message
 -v  --verbosity <level>            CRITICAL, ERROR, WARNING, INFO, DEBUG
 -i  --ntop-iface-name <name>       Interface name reported to ntop (default: w00t)
 -a  --ntop-probe-addr <addr>       Address of this probe reported to ntop (default: 127.0.0.1)
 -z  --zmq-bind-addr <zmq addr fmt> ZMQ bind address, example: tcp://10.0.0.0:5555 or tcp://*:5555 (default)
 -p  --netflow-v5-port <port>       NetflowV5 port (default 2055)
 -b  --netflow-v5-bind <bind addr>  NetflowV5 bind address (default 0.0.0.0)
	""")

try:
	opts, args = getopt.getopt(sys.argv[1:], "hv:i:a:z:p:b:", ["help", "verbosity=", 
		"ntop-iface-name=", 
		"ntop-probe-addr=", 
		"zmq-bind-addr=", 
		"netflow-v5-port=",
		"netflow-v5-bind="
		])
	for o, a in opts:
		if o in ("-v",):
			log_level = a.upper()
			valid_log_levels = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]
			if log_level not in valid_log_levels:
				sys.exit("Invalid log level '%s'. Valid: %s" % (log_level, valid_log_levels))		
		elif o in ("-h", "--help"):
			halp(); sys.exit()
		elif o in ("-i", "--ntop-iface-name"):
			ntop_iface_name = a
		elif o in ("-a", "--ntop-probe-address"):
			ntop_probe_addr = a
		elif o in ("-z", "--zmq-bind-address"):
			zmq_server = a
		elif o in ("-p", "--netflow-v5-port"):
			netflow_v5_port = a
		elif o in ("-b", "--netflow-v5-bind"):
			netflow_v5_addr = a
		else:
			assert False, "Unhandled option: %s, use -h for options" % (o,)
except getopt.GetoptError as err:
	logging.critical(str(err))
	sys.exit(2)

logging.basicConfig(level=log_level)

logging.info("Setting netflowV5 socket: %s:%s" % (netflow_v5_addr, netflow_v5_port))
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind((netflow_v5_addr, netflow_v5_port))
except Exception as e:
	logging.critical("Error binding netflowV5 socket on '%s:%s': %s" % (netflow_v5_addr, netflow_v5_port, e))
	sys.exit(1)

logging.info("Setting up ZMQ: '%s' as server(PUB)" % (zmq_server))
try:
	zmq_context = zmq.Context()
	zmq_socket = zmq_context.socket(zmq.PUB)
	zmq_socket.bind(zmq_server)
except Exception as e:
	logging.critical("Error setting up ZMQ as PUB on '%s': %s" % (zmq_server, e))
	sys.exit(1)
	
#
# zmq publisher functions
#
def ntop_pub_iface(name, ip, speed=1000, byte_cnt=0, packet_cnt=0, avg_bps=0, avg_pps=0, zmq_flow_exports=0):
    iface_stats = {
    "iface": { 
        "name": name, 
        "speed": speed, 
        "ip": "" 
    }, 
    "probe": { "ip": ip, "public_ip": "" }, 
    "time" : datetime.datetime.utcnow().timestamp(), 
    "bytes": byte_cnt, 
    "packets": packet_cnt, 
    "avg": { "bps": avg_bps, "pps": avg_pps }, 
    "drops" : { 
        "export_queue_too_long": 0, 
        "too_many_flows": 0, 
        "elk_flow_drops": 0, 
        "sflow_pkt_sample_drops": 0,  
        "flow_collection_drops": 0 
    }, 
    "timeout": { "lifetime": 120, "idle": 30 },  
    "zmq": { "num_flow_exports": zmq_flow_exports, "num_exporters": 1 }
    }
    iface_stats_json = json.dumps(iface_stats).encode()
    logging.debug("ZMQ event:\n%s" % (str(iface_stats_json)))
    # FIXME improve the generation of this string...
    topic = b'event\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\xb2\x00\x00\x03\x21'
    zmq_socket.send_multipart([topic, iface_stats_json])

def ntop_pub_flow(src_addr, src_port, dst_addr, dst_port, in_pkts, in_bytes, tcp_flags, proto, exporter_address, probe_address):
    now = datetime.datetime.utcnow().timestamp()
    flow_data = {
     "IPV4_SRC_ADDR": src_addr
    ,"IPV4_DST_ADDR": dst_addr
    ,"INPUT_SNMP": 0  #FIXME should get that from the netflow pkt
    ,"OUTPUT_SNMP": 0 #FIXME should get that from the netflow pkt
    ,"IN_PKTS" : in_pkts      #"IN_PKTS":2,
    ,"IN_BYTES" : in_bytes     #"IN_BYTES":104,
    ,"FIRST_SWITCHED": now          #"FIRST_SWITCHED":1564262418,
    ,"LAST_SWITCHED": now          #"LAST_SWITCHED":1564262419,
    ,"L4_SRC_PORT" : src_port     #"L4_SRC_PORT":34554,
    ,"L4_DST_PORT": dst_port     #"L4_DST_PORT":443,
    ,"TCP_FLAGS" : tcp_flags    #"TCP_FLAGS":17,
    ,"PROTOCOL" : proto        #"PROTOCOL":6,
    ,"SRC_TOS" : 0 #FIXME should get that from the netflow pkt
    ,"SRC_AS": 0   #FIXME should get that from the netflow pkt
    ,"DST_AS": 0   #FIXME should get that from the netflow pkt
    ,"EXPORTER_IPV4_ADDRESS": exporter_address #"EXPORTER_IPV4_ADDRESS":"192.168.0.1",
    ,"35632.57943": probe_address #ntopng/nprobe specific?
    }
    flow_json = json.dumps(flow_data).encode()
    logging.debug("ZMQ flow:\n%s" % (str(flow_json)))
    # FIXME improve the generation of this string...
    topic = b'flow\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\xb2\x00\x00\x03\x21'
    zmq_socket.send_multipart([topic, flow_json])


if __name__ == "__main__":
	
	# netflow reportrs data (key is sensor_ip, value is info hash)
	nflow_reporters = {}
	
	logging.warning("Waiting for netflow packets...")
	while True:

		# FIXME does this queue received packages? or should the zmq pub be done async?		
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
		sensor_ip = str(sensor_address[0])	
		logging.debug("Got packet from:%s" % (sensor_ip))

        # TODO should remove those after some time of inactivity...
		if sensor_ip not in nflow_report_threads:
			nflow_reporters[sensor_ip] = {
				"packet_count": 0,
				"bytes_count" : 0,
				"record_count"  : 0
			}

			logging.info("A wild netflow reporter appeared, starting  ntopng iface reporter thread for %s" % (sensor_ip))
			def report_metrics(sensor_ip):
				nflow_data = nflow_reporters[sensor_ip]
				while True:
					b_count = nflow_data["bytes_count"] ; nflow_data["bytes_count"] = 0	
					p_count = nflow_data["packet_count"]; nflow_data["packet_count"] = 0
					r_count = nflow_data["record_count"]; nflow_data["record_num"] = 0
					logging.debug("Sending metrics for %s: bytes:%s pkts:%s records:%s" % (sensor_ip, b_count, p_count, r_count))
					ntop_pub_iface(ntop_iface_name, sensor_ip,
						byte_cnt  = b_count,
						packet_cnt= p_count,
						avg_bps   = b_count, # TODO this needs to be improved 
						avg_pps   = p_count, # TODO this needs to be improved
						zmq_flow_exports = r_count)
					time.sleep(1)
			t = threading.Thread(target=report_metrics,args=(sensor_ip))
			t.daemon=True
			t.start()
			nflow_reports[sensor_ip]["thread"] = t
            
		nflow_data = nflow_reporters[sensor_ip]	
		try:
			packet_keys = ["netflow_version","flow_count","sys_uptime","unix_secs","unix_nsecs","flow_seq","engine_type","engine_id"] # Netflow v5 packet fields
			packet_values = struct.unpack('!HHIIIIBB',flow_packet_contents[0:22]) # Version of NF packet and count of Flows in packet
			packet_contents = dict(zip(packet_keys,packet_values)) # v5 packet fields and values
		except Exception as e:
			logging.warning("Failed unpacking header received from %s: %s" % (sensor_ip, e))
			continue
		
		if packet_contents["netflow_version"] != 5:
			logging.warning("Received a non-v5 Netflow packet from %s: version:%s" % (sensor_ip, package_contents["netflow_version"]))
			continue

		flow_count = packet_contents["flow_count"]
		for flow_num in range(0, flow_count):
			now = datetime.datetime.utcnow() # Timestamp for flow rcv
			logging.debug("Parsing flow %s/%s" % (flow_num, flow_count))
			
			base = packet_header_size + (flow_num * flow_record_size)
			(ip_source,
			ip_destination,
			next_hop,
			input_interface,
			output_interface,
			total_packets,
			total_bytes,
			sysuptime_start,
			sysuptime_stop,
			src_port,
			dest_port,
			pad,
			tcp_flags,
			protocol_num,
			type_of_service,
			source_as,
			destination_as,
			source_mask,
			destination_mask) = struct.unpack('!4s4s4shhIIIIHHcBBBhhBB',flow_packet_contents[base+0:base+46])

			nflow_data["packet_count"] += total_packets    
			nflow_data["bytes_count"]  += total_bytes

			ntop_pub_flow(
				inet_ntoa(ip_source), 
				src_port, 
				inet_ntoa(ip_destination), 
				dest_port, 
				total_packets, 
				total_bytes, 
				tcp_flags, 
				protocol_num, 
				sensor_address, 
				ntop_probe_addr
			)
			
			nflow_data["record_count"] += 1

