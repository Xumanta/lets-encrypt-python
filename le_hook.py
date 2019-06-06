#!/usr/bin/python

import requests
import json
import logging
import ovh
import dns.resolver
from tldextract import extract
from f5.bigip import ManagementRoot
from f5.bigip.contexts import TransactionContextManager
import os
import sys
import time

requests.packages.urllib3.disable_warnings()

# slurp credentials
with open('config/f5creds.json', 'r') as f:
    config = json.load(f)
f.close()

f5_host = config['f5host']
f5_user = config['f5acct']
f5_password = config['f5pw']

# Logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

##OVH Setup
# create a client using configuration
client = ovh.Client()
## Getting Domain Zone
resultzone = client.get('/domain/zone')
# Choosing first zone (and in my case the only one)
zone = resultzone[0]
zonebaseurl = '/domain/zone/' + zone + '/'
## Getting DNS Servers for validation
resultdnservers = client.get('/domain/zone/'+zone)
dnsserver = resultdnservers['nameServers']


# Resolve IPs for nameservers
resolver = dns.resolver.Resolver()
ovhdns_servers = [item.address for server in dns_servers
                  for item in resolver.query(server)]


def _has_dns_propagated(name, token):
    successes = 0
    for dns_server in ovhdns_servers:
        resolver.nameservers = [dns_server]

        try:
            dns_response = resolver.query(name, 'txt')
        except dns.exception.DNSException as error:
            return False

        text_records = [record.strings[0] for record in dns_response]
        for text_record in text_records:
            if text_record == token:
                successes += 1

    if successes == 2:
        logger.info(" + (hook) All challenge records found!")
        return True
    else:
        return False


def create_txt_record(args):
    """
    Create a TXT DNS record via ovh.com's DNS API
    """
    domain_name, token = args[0], args[2]
    fqdn_tuple = extract(domain_name)
    base_domain_name = ".".join([fqdn_tuple.domain, fqdn_tuple.suffix])

    if fqdn_tuple.subdomain is '':
        txtrecord = u'_acme-challenge'
    else:
        txtrecord = u'_acme-challenge.{0}'.format(fqdn_tuple.subdomain)
    name = "{0}.{1}".format(txtrecord, base_domain_name)

    ## Creating TXT Record
    result = client.post(zonebaseurl + 'record',
                         fieldType='TXT',
                         subDomain=txtrecord,
                         target=token,
                         ttl=0
                         )
    # Pretty print
    logger.info(" + (hook) TXT Created: " + json.dumps(result, indent=4))

    ## Saving Record onto DNS Zone
    refreshres = client.post(zonebaseurl + 'refresh')
    # Pretty print
    print(json.dumps(refreshres, indent=4))


    logger.info(" + (hook) Settling down for 10s...")
    time.sleep(10)

    while not _has_dns_propagated(name, token):
        logger.info(" + (hook) DNS not propagated, waiting 30s...")
        time.sleep(30)


def delete_txt_record(args):
    """
    Delete the TXT DNS challenge record via name.com's DNS API
    """
    domain_name = args[0]
    fqdn_tuple = extract(domain_name)
    base_domain_name = ".".join([fqdn_tuple.domain, fqdn_tuple.suffix])
    if fqdn_tuple.subdomain is '':
        txtrecord = u'_acme-challenge'
    else:
        txtrecord = u'_acme-challenge.{0}'.format(fqdn_tuple.subdomain)
    ## Getting all TXT Records
    restxts = client.get(zonebaseurl + 'record',
                         fieldType='TXT',
                         subDomain=txtrecord,
                         )
    ## Delete each TXT Record on that subdomain
    for id in restxts:
        result = client.delete(zonebaseurl + 'record/' + str(id))
    ## Saving deletion onto DNS Zone
    refreshres = client.post(zonebaseurl + 'refresh')
    logger.info(" + (hook) TXT record deleted!")


def deploy_cert(args):
    domain = args[0]
    key = args[1]
    cert = args[2]
    chain = args[4]

    mr = ManagementRoot(f5_host, f5_user, f5_password)

    # Upload files
    mr.shared.file_transfer.uploads.upload_file(key)
    mr.shared.file_transfer.uploads.upload_file(cert)
    mr.shared.file_transfer.uploads.upload_file(chain)

    # Check to see if these already exist
    key_status = mr.tm.sys.file.ssl_keys.ssl_key.exists(
        name='{0}.key'.format(domain))
    cert_status = mr.tm.sys.file.ssl_certs.ssl_cert.exists(
        name='{0}.crt'.format(domain))
    chain_status = mr.tm.sys.file.ssl_certs.ssl_cert.exists(name='le-chain.crt')

    if key_status and cert_status and chain_status:

        # Because they exist, we will modify them in a transaction
        tx = mr.tm.transactions.transaction
        with TransactionContextManager(tx) as api:

            modkey = api.tm.sys.file.ssl_keys.ssl_key.load(
                name='{0}.key'.format(domain))
            modkey.sourcePath = 'file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(key))
            modkey.update()

            modcert = api.tm.sys.file.ssl_certs.ssl_cert.load(
                name='{0}.crt'.format(domain))
            modcert.sourcePath = 'file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(cert))
            modcert.update()

            modchain = api.tm.sys.file.ssl_certs.ssl_cert.load(
                name='le-chain.crt')
            modchain.sourcePath = 'file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(chain))
            modchain.update()

            logger.info(
                " + (hook) Existing Certificate/Key updated in transaction.")

    else:
        newkey = mr.tm.sys.file.ssl_keys.ssl_key.create(
            name='{0}.key'.format(domain),
            sourcePath='file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(key)))
        newcert = mr.tm.sys.file.ssl_certs.ssl_cert.create(
            name='{0}.crt'.format(domain),
            sourcePath='file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(cert)))
        newchain = mr.tm.sys.file.ssl_certs.ssl_cert.create(
            name='le-chain.crt',
            sourcePath='file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(chain)))
        logger.info(" + (hook) New Certificate/Key created.")

    # Create SSL Profile if necessary
    if not mr.tm.ltm.profile.client_ssls.client_ssl.exists(
            name='cssl.{0}'.format(domain), partition='Common'):
        cssl_profile = {
            'name': '/Common/cssl.{0}'.format(domain),
            'cert': '/Common/{0}.crt'.format(domain),
            'key': '/Common/{0}.key'.format(domain),
            'chain': '/Common/le-chain.crt',
            'defaultsFrom': '/Common/clientssl'
        }
        mr.tm.ltm.profile.client_ssls.client_ssl.create(**cssl_profile)


def unchanged_cert(args):
    logger.info(" + (hook) No changes necessary. ")


def main(argv):
    """
    The main logic of the hook.
    letsencrypt.sh will pass different arguments for different types of
    operations. The hook calls different functions based on the arguments
    passed.
    """
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge': delete_txt_record,
        'deploy_cert': deploy_cert,
        'unchanged_cert': unchanged_cert,
    }
    logger.info(" + (hook) executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
