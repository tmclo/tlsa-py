# tlsa record auto updater for cloudflare

To use this project first clone it and then install the requirements as such:
```bash
python3 -m pip install -r requirements.txt
```

Then update the lines `zone_name` and `cf_api_key` in main.py in order to use the cloudflare api

You can then use this code in a cron job to automatically update your TLSA records with CloudFlare each time you renew your LetsEncrypt certificates as such:
```bash
python3 ~/tlsa-py/main.py /etc/letsencrypt/live/example.com (no trailing slash)
```