## Planned Changes

To make this project working for me I plan to use ovh.com's api and therefore rewrite the given python hook for it.

Work in progress!

Planned Setup atm:
- Put application details into ovh.conf (https://github.com/ovh/python-ovh#1-create-an-application)
- request_token.py
- Put given Consumer Token into ovh.conf
- Usage as mentioned down here

## Synopsis

This project uses Lukas2511's letsencrypt.sh shell script as the basis for deploying certificates to an F5 BIG-IP.

It utilizes the DNS challenge and reaches out to name.com's API (currently beta) for the challenge setup and teardown. Major (below reference) has example for Rackspace DNS that this is based on.

It utilizes F5's iControl REST interface to upload and configure the certificates into a clientssl profile for SSL offloading capability.

## Usage

./letsencrypt.sh -c -f /var/tmp/le/config/config.sh

where the configuration options are defined as appropriate in config.sh

## Contributors

Much of this project is based on the work of these projects:

* https://devcentral.f5.com/codeshare/lets-encrypt-on-a-big-ip
* https://github.com/lukas2511/letsencrypt.sh
* https://github.com/sporky/letsencrypt-dns
* https://github.com/major/letsencrypt-rackspace-hook
