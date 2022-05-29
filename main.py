import sys
import hashlib
from pathlib import Path
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import CloudFlare

# Using static variables instead of .env file for portability
# You could look into using something like HashiCorp Vault or environment variables
# an example of using environment variables would be to add/modify the following lines
# import os (<- add this to the top of the file)
# zone_name = os.environ.get("ZONE_NAME")
# cf_api_key = os.environ.get("CF_API_KEY")
zone_name = "example.com"
cf_api_key = "-aPikEyeXamplE"

if len(sys.argv) < 2:
    exit('Usage: python3 ' + sys.argv[0] + ' /etc/ssl/certs (no trailing slash)')

def main():
    certificate_dir = sys.argv[1]

    cf = CloudFlare.CloudFlare(token=cf_api_key)

    try:
        zones = cf.zones.get(params = {'name':zone_name,'per_page':1})
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones.get %d %s - api call failed' % (e, e))
    except Exception as e:
        exit('/zones.get - %s - api call failed' % (e))

    if len(zones) == 0:
        exit('No zones found')

    zone = zones[0]
    zone_id = zone['id']

    with open(certificate_dir + '/cert.pem', 'rb') as f:
        dane_ee = x509.load_pem_x509_certificate(f.read(), default_backend())

    dane_ee_pubkey = dane_ee.public_key()
    dane_ee_pubkey_bytes = dane_ee_pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest_ee = hashlib.sha256(dane_ee_pubkey_bytes).hexdigest()

    with open(certificate_dir + '/chain.pem', 'rb') as t:
        dane_ta = x509.load_pem_x509_certificate(t.read(), default_backend())

    dane_ta_pubkey = dane_ta.public_key()
    dane_ta_pubkey_bytes = dane_ta_pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest_ta = hashlib.sha256(dane_ta_pubkey_bytes).hexdigest()

    # check/create TLSA records & update accordingly if exist
    params = {
        "type": "TLSA",
    }

    try:
        records = cf.zones.dns_records.get(zone_id, params=params)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones.get - %s - api call failed' % (e))
    except Exception as e:
        exit('/zones.get - %s - api call failed' % (e))

    for i in records:
        if "2 1 1" in i['content']:
            # update DANE_TA record
            update_records(cf, zone_name, zone_id, 2, 1, 1, digest_ta, i['id'])
            print("DANE_TA record updated successfully: " + digest_ta)
        elif "3 1 1" in i['content']:
            # update DANE_EE Record
            update_records(cf, zone_name, zone_id, 3, 1, 1, digest_ee, i['id'])
            print("DANE_EE record updated successfully: " + digest_ee)
        else:
            if "3 1 1" in i['content']:
                create_record(cf, zone_name, zone_id, 2, 1, 1, digest_ta)
            elif "2 1 1" in i['content']:
                create_record(cf, zone_name, zone_id, 3, 1, 1, digest_ee)
            else:
                create_record(cf, zone_name, zone_id, 2, 1, 1, digest_ta)
                create_record(cf, zone_name, zone_id, 3, 1, 1, digest_ee)

    exit(0)

def update_records(cf, zone_name, zone_id, usage, selector, matching_type, certificate, record_id):
    dns_record = {
        'type':'TLSA',
        'name':'_25._tcp.mail.' + zone_name,
        'ttl':60,
        'data':{
            'usage':usage,
            'selector':selector,
            'matching_type':matching_type,
            'certificate':certificate,
        },
    }

    try:
        dns_record = cf.zones.dns_records.put(zone_id, record_id, data=dns_record)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones.dns_records.put %s - %d %s - api call failed' % (zone_name, e, e))

def create_record(cf, zone_name, zone_id, usage, selector, matching_type, certificate):
    dns_record = {
        'type':'TLSA',
        'name':'_25._tcp.mail.' + zone_name,
        'ttl':60,
        'data':{
            'usage':usage,
            'selector':selector,
            'matching_type':matching_type,
            'certificate':certificate,
        },
    }

    try:
        r = cf.zones.dns_records.post(zone_id, data=dns_record)
        print("Successfully created record: " + certificate)
    except CloudFlare.CloudFlareAPIError as e:
        exit('/zones.dns_records.post %s - %d %s' % (e, e))

if __name__ == '__main__':
    main()