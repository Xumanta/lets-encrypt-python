#!/usr/bin/python3

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

# OVH Setup
# create a client using configuration
client = ovh.Client()
# Getting Domain Zone
resultzone = client.get('/domain/zone')
# Choosing first zone (and in my case the only one)
zone = resultzone[0]
zonebaseurl = '/domain/zone/' + zone + '/'

def _has_dns_propagated(name, token):
    dns_servers = ['1.1.1.1','1.0.0.1','8.8.8.8']
    resolver = dns.resolver.Resolver()
    btoken =  "b'" + token + "'"
    successes = 0
    for dns_server in dns_servers:
        resolver.nameservers = [dns_server]

        try:
            dns_response = resolver.query(name, 'txt')
        except dns.exception.DNSException as error:
            return False

        text_records = [record.strings[0] for record in dns_response]
        for text_record in text_records:
            if str(text_record) == btoken:
                successes += 1

    if successes == 3:
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

    # Creating TXT Record
    result = client.post(zonebaseurl + 'record',
                         fieldType='TXT',
                         subDomain=txtrecord,
                         target=token,
                         ttl=0
                         )
    # Pretty print
    logger.info(" + (hook) TXT Created: " + json.dumps(result, indent=4))

    # Saving Record onto DNS Zone
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
    if fqdn_tuple.subdomain is '':
        txtrecord = u'_acme-challenge'
    else:
        txtrecord = u'_acme-challenge.{0}'.format(fqdn_tuple.subdomain)
    # Getting all TXT Records
    restxts = client.get(zonebaseurl + 'record',
                         fieldType='TXT',
                         subDomain=txtrecord,
                         )
    # delete each TXT Record on that sub-domain
    for recordid in restxts:
        result = client.delete(zonebaseurl + 'record/' + str(recordid))
        logger.info(" + (hook) Deleted Record (null): %s" % json.dumps(result, indent=4))
    # Saving deletion onto DNS Zone
    client.post(zonebaseurl + 'refresh')
    logger.info(" + (hook) TXT record deleted!")


def deploy_cert(args):
    domain = args[0]
    key = args[1]
    cert = args[2]
    chain = args[4]

    ffivemr = ManagementRoot(f5_host, f5_user, f5_password)

    # Upload files
    ffivemr.shared.file_transfer.uploads.upload_file(key)
    ffivemr.shared.file_transfer.uploads.upload_file(cert)
    ffivemr.shared.file_transfer.uploads.upload_file(chain)

    # Check to see if these already exist
    key_status = ffivemr.tm.sys.file.ssl_keys.ssl_key.exists(
        name='{0}.key'.format(domain))
    cert_status = ffivemr.tm.sys.file.ssl_certs.ssl_cert.exists(
        name='{0}.crt'.format(domain))
    chain_status = ffivemr.tm.sys.file.ssl_certs.ssl_cert.exists(name='le-chain.crt')

    if key_status and cert_status and chain_status:

        # Because they exist, we will modify them in a transaction
        tx = ffivemr.tm.transactions.transaction
        with TransactionContextManager(tx) as txapi:

            modkey = txapi.tm.sys.file.ssl_keys.ssl_key.load(
                name='{0}.key'.format(domain))
            modkey.sourcePath = 'file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(key))
            modkey.update()

            modcert = txapi.tm.sys.file.ssl_certs.ssl_cert.load(
                name='{0}.crt'.format(domain))
            modcert.sourcePath = 'file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(cert))
            modcert.update()

            modchain = txapi.tm.sys.file.ssl_certs.ssl_cert.load(
                name='le-chain.crt')
            modchain.sourcePath = 'file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(chain))
            modchain.update()

            logger.info(
                " + (hook) Existing Certificate/Key updated in transaction.")

    else:
        newkey = ffivemr.tm.sys.file.ssl_keys.ssl_key.create(
            name='{0}.key'.format(domain),
            sourcePath='file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(key)))
        newcert = ffivemr.tm.sys.file.ssl_certs.ssl_cert.create(
            name='{0}.crt'.format(domain),
            sourcePath='file:/var/config/rest/downloads/{0}'.format(
                os.path.basename(cert)))
        if not chain_status:
            logger.info(" + (hook) No LE-Chain found - deploying now")
            newchain = ffivemr.tm.sys.file.ssl_certs.ssl_cert.create(
                name='le-chain.crt',
                sourcePath='file:/var/config/rest/downloads/{0}'.format(
                    os.path.basename(chain)))
        logger.info(" + (hook) New Certificate/Key created.")

    # Create SSL Profile if necessary
    if not ffivemr.tm.ltm.profile.client_ssls.client_ssl.exists(
            name='cssl.{0}'.format(domain), partition='Common'):
        cssl_profile = {
            'name': '/Common/cssl.{0}'.format(domain),
            'cert': '/Common/{0}.crt'.format(domain),
            'key': '/Common/{0}.key'.format(domain),
            'chain': '/Common/le-chain.crt',
            'defaultsFrom': '/Common/clientssl'
        }
        ffivemr.tm.ltm.profile.client_ssls.client_ssl.create(**cssl_profile)


def unchanged_cert(args):
    logger.info(" + (hook) No changes necessary. ")

def invalid_challenge(args):
    domain, response = args[0], args[1]
    logger.warning("Challenge for domain '%s' was invalid, please have a look: %s", domain, response)
    return

def request_failure(args):
    status_code, reason = args[0], args[1]
    logger.warning("Request to Let's Encrypt failed: %s", reason)
    return

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
        'invalid_challenge': invalid_challenge,
        'request_failure': request_failure,
    }
    
    # Log level
    log_level = PATTERN_LOG_LEVEL.findall(argv[0])
    if log_level:
        level = log_level[0].lower()
        if level in ('warn', 'warning'):
            logger.setLevel(logging.WARNING)
        elif level == 'info':
            logger.setLevel(logging.INFO)
        elif level == 'debug':
            logger.setLevel(logging.DEBUG)
        argv.pop(0)

    action = argv[0]
    args = argv[1:]
    if action not in ops:
        return

    ops[action](args)
    
    #logger.info(" + (hook) executing: {0}".format(argv[0]))
    #ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
