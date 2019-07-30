# netflow2ntopng
[Netflow](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-netflow/index.html) v5 to [NTOPNG](https://www.ntop.org/products/traffic-analysis/ntop/) reporter/converter/hack

# DISCLAIMER: 
This is not stable, was thrown together in one day, use only for testing  
Please use [nProbe](https://www.ntop.org/products/netflow/nprobe/) for production environments where you actually care about your network metrics

## What is this for?
This receives netflow V5 packets( from rflow/fprobe/etc) on port 2055(default)  
and reports them via ZMQ(ZeroMQ) to NTOPNG.  
This **should** support more than one netflow reporter, but YMMV.
  
### Setup where I used this:  
* [ddwrt](https://dd-wrt.com/) router with [optware](https://wiki.dd-wrt.com/wiki/index.php/Optware)
  * installed [fprobe](https://sourceforge.net/projects/fprobe/) since rflow wasn't available
  * run on router with: `fprobe -i br0 <netflow2ntopng addr>:2055`
* raspberry pi 4 with ntopng(default repo) and this script
  * run this `python3 netflow2ntopng.py -v info -i ddwrt -z tcp://localhost:5555`
  * ntopng `sudo -u ntopng ntopng -i tcp://localhost:5555 -m <local network cidr>` (you probably want this as a service)

### Why not use NTOPNG and/or nProbe?
At this time, nProbe doesn't seem to support Raspbian 10 (buster) out-of-the-box, having dependency issues. See [this](https://github.com/ntop/ntopng/issues/2706) 
Also, NTOPNG doesn't seem to be able to run on ddwrt (needs local interface to sniff traffic)

## Command-line options
```
 -h  --help                         Show this help message
 -v  --verbosity <level>            CRITICAL, ERROR, WARNING, INFO, DEBUG
 -i  --ntop-iface-name <name>       Interface name reported to ntop (default: w00t)
 -a  --ntop-probe-addr <addr>       Address of this probe reported to ntop (default: 127.0.0.1)
 -z  --zmq-bind-addr <zmq addr fmt> ZMQ bind address, example: tcp://10.0.0.0:5555 or tcp://*:5555 (default)
 -p  --netflow-v5-port <port>       NetflowV5 port (default 2055)
 -b  --netflow-v5-bind <bind addr>  NetflowV5 bind address (default 0.0.0.0)
```

## Know issues
1. first 'event' message is treated as corrputed by ntopng
1. some netflow v5 fields are ignored (input/output SNMP, SRC_TOS, SRC/DEST AS)
1. avg_bps and avg_pps also are weird
1. this is not setup to run as a service, but shouldn't be too hard support externally
1. this doesn't support IPV6? well, netflow v5 doesn't
