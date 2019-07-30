## General

This project uses Lukas2511's dehydrated shell script as the basis for deploying certificates to an F5 BIG-IP.

For the DNS challende it uses OVH.com's API for deployment and then utilizes F5's iControl REST interface to upload and configure the certificates into a clientssl profile for SSL offloading capability.

Thanks to ACMEv2 its also possible to deploy wildcard certificates. The clientssl profile will have the asterisk replaced for the wildcard domain with "wildcard".

## Usage

1. You need to create an application within OVH (https://github.com/ovh/python-ovh#1-create-an-application)
2. Put the app details into ovh.conf - except consumer key
3. Run request_token.py to get a consumer key
4. Put the consumer key also into ovh.conf
5. Make sure your domains are in config/domains.txt and your using the correct Let's Encrypt API (config/config.sh)
6. Run ./dehydrated --accept-terms -c -f /opt/lead/lets-encrypt-python/config/config.sh
7. (recommended) Turn it into a cron job


## Contributors

Big Credit for Lukas2511:
* https://github.com/lukas2511/dehydrated

This project is based on f5devcentrals deployment:
* https://github.com/f5devcentral/lets-encrypt-python

And also Thanks to these projects:
* https://github.com/ovh/python-ovh
* https://github.com/rbeuque74/letsencrypt-ovh-hook/
