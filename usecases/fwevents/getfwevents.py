'''
	Retrieves all firewall events from 'start' to 'end' in chunks of 'delta'.

	This is to make sure we don't reach the 50k events limit.
	Depending on the amount of events per time slot, 'delta' must be decreased.
'''


from dsp3.models.manager import Manager
import time
from datetime import datetime, timedelta
import sys
import csv
import suds


def obj_to_dictionary(field_names, obj):
    tempDict = {}
    for field in field_names:
        try:
            iterator = iter(obj[field])
        except TypeError:
            tempDict[field] = obj[field]
        else:
            if isinstance(obj[field], suds.sax.text.Text):
                tempDict[field] = obj[field]
            else:
                tempDict[field] = type(obj[field]).__name__

    return tempDict


def process_event_list(file_name, events):
    fields = events[0].__keylist__
    file = open('%s.csv' % file_name , 'w')
    with file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for event in events:
            writer.writerow(obj_to_dictionary(fields, event))


dsm = Manager(tenant='', username='', password='', verify_ssl=True)


print("Connected to Deep Security SaaS")
print("Session ID: " + dsm.session_id)
print("Retrieving firewall events (may take a while)...")


start = datetime.now()
end = start - timedelta(days=7)
delta = timedelta(hours=1)


print("Using " + str(delta) + " deltas.")

fw_events = []

while (start > end):
	chunk = dsm.fw_event_retrieve(range_from=(start - delta), range_to=start, time_type='CUSTOM_RANGE')
	print("Chunk " + str(start), end='')
	if (chunk):
		chunk_size = len(chunk)
		if (chunk == 50000):
			print("WARNING: reached max size. Try a smaller delta.")
		print(" written, retrieved " + str(chunk_size) + " events.")
		fw_events.extend(chunk)
	else:
		print(" is empty.")
	start = (start - delta)

dsm.end_session()

print("Retrieved " + str(len(fw_events)) + " events (" + str(sys.getsizeof(fw_events)) + " bytes).")

print("Writing to file... ", end='')

process_event_list('fw_events', fw_events)

print("Done!")