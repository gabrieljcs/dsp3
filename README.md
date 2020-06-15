![alt tag](/docs/source/_static/dsp3_logo3.png?raw=true "DSP3")

[![Downloads](https://pepy.tech/badge/dsp3)](https://pepy.tech/project/dsp3)

DSP3
====
[![Build Status](https://travis-ci.org/jeffthorne/DSP3.svg?branch=master)](https://travis-ci.org/jeffthorne/deep_security)

A Python 3 compatible SDK for Trend Micro's Deep Security platform.<br/>
Current Status: Experimental

## Installation
pip install dsp3


## Documentation
http://dsp3.readthedocs.io

## Examples

To run use cases from project dir as an example: python -m examples.alerts<br/>

1.  Authentication: [examples/authentication.py](examples/authentication.py)
2.  Get events: [examples/get_events.py](examples/get_events.py)
3.  Create block by file hash rules: [examples/block_by_hash.py](examples/block_by_hash.py)
4.  Get manager info: [examples/manager_info.py](examples/manager_info.py)
5.  Alerts: [examples/alerts.py](examples/alerts.py)
6.  Host/s operations: [examples/host.py](examples/host.py)
7.  Administrators: [examples/administrators.py](examples/administrators.py)
8.  Event based tasks: [examples/event_based.py](examples/event_based.py)
9.  Relays: [examples/relays.py](examples/relays.py)
10. Scripts: [examples/scripts.py](examples/scripts.py)
11. Reports: [examples/reports.py](examples/reports.py)

## Use Cases
The following examples are some use cases seen in the field.<br/>
To run use cases from project dir: python -m usecases.eventscsv.eventscsv

1. Retrieve events to csv files: [usecases/eventscsv/eventscsv.py](usecases/eventscsv/eventscsv.py)
2. Retrieve all firewall events to csv files by using delta chunks: [usecases/fwevents/getfwevents.py](usecases/fwevents/getfwevents.py)
    
    The chunks must be used in order to avoid reaching the 50k per request limitation when there are too many events.