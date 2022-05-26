import os
import sys
import CloudFlare
from dotenv import load_dotenv
from pathlib import Path

dotenv_path = Path('./.env')
load_dotenv(dotenv_path=dotenv_path)
if len(sys.argv) < 3:
    exit('Usage: python3 ' + sys.argv[0] + ' usage_id record_id certificate')

def main():
    usage_id = sys.argv[1]
    record_id = sys.argv[2]
    certificate = sys.argv[3]
    zone_name = os.getenv('ZONE_NAME')
    
    cf = CloudFlare.CloudFlare(token=os.getenv('CF_API_KEY'))
    
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

        
    try:
        dns_records = cf.zones.dns_records.get(zone_id)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones/dns_records.get %d %s - api call failed' % (e, e))
        
    update_records(cf, zone_name, zone_id, usage_id, record_id, certificate)
        

    exit(0)
    
def update_records(cf, zone_name, zone_id, usage_id, record_id, certificate):
    dns_record = {
        'type':'TLSA',
        'name':'_25._tcp.mail.' + zone_name,
        'ttl':60,
        'data':{
            'usage':usage_id,
            'selector':1,
            'matching_type':1,
            'certificate':certificate,
        },
    }
    
    try:
        dns_record = cf.zones.dns_records.put(zone_id, record_id, data=dns_record)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones.dns_records.put %s - %d %s - api call failed' % (zone_name, e, e))

if __name__ == '__main__':
    main()