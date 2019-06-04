# -*- encoding: utf-8 -*-

import ovh
import json

# create a client using configuration
client = ovh.Client()

# Read /me only, to check if its working
# Read /domain* to be able to read out your zoneName, but has to be given here!
# Read/Write for /domain/zone/{zoneName}/refresh to flush the changes onto the DNS Servers
# Read/Write for /domain/zone/{zoneName}/record to make TXT Records and delete them afterwards
ck = client.new_consumer_key_request()
ck.add_rules(ovh.API_READ_ONLY, "/me")
ck.add_rules(ovh.API_READ_WRITE, "/domain/zone/{zoneName}/refresh")
ck.add_recursive_rules(ovh.API_READ_ONLY, "/domain")
ck.add_recursive_rules(ovh.API_READ_WRITE, "/domain/zone/{zoneName}/record")

# Request token
validation = ck.request()

print("Please visit %s to authenticate" % validation['validationUrl'])
input("and press Enter to continue...")

# Print nice welcome message
print("Welcome", client.get('/me')['firstname'])
print("Your consumerKey is:  %s" % validation['consumerKey'])
print("Please put it in the ovh.conf file to make the script working!")
