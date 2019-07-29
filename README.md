## Changes

I changed the dns api from name.com's one to ovh - therefore the python hook got the most changes.

Atm I want to add LetsEncrypts WildCard Support, but for this theres more changes needed..

Work in progress!

Setup:
- Put application details into ovh.conf (https://github.com/ovh/python-ovh#1-create-an-application)
- Fill in the zone name in request_token.py und run it, to get a consumer key
- Put given consumer key into ovh.conf
- Usage as mentioned down here

## Synopsis

This project uses Lukas2511's dehydrated shell script as the basis for deploying certificates to an F5 BIG-IP.

It utilizes the DNS challenge and reaches out to ovh.com's API (currently beta) for the challenge setup and teardown. Major (below reference) has example for Rackspace DNS that this is based on.

It utilizes F5's iControl REST interface to upload and configure the certificates into a clientssl profile for SSL offloading capability.

## Usage

./dehydrated --accept-terms -c -f /opt/lead/lets-encrypt-python/config/config.sh

where the configuration options are defined as appropriate in config.sh

## Contributors

Much of this project is based on the work of these projects:

* https://devcentral.f5.com/codeshare/lets-encrypt-on-a-big-ip
* https://github.com/lukas2511/dehydrated
* https://github.com/sporky/letsencrypt-dns
* https://github.com/major/letsencrypt-rackspace-hook
* https://github.com/rbeuque74/letsencrypt-ovh-hook/
