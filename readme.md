# TLSA Record Automation in Python

### What does this project achieve?

I wrote this project after setting up TLSA keys for my mail server and realising that due to using LetsEncrypt I would have to manually regenerate and update the TLSA keys in my cloudflare account each time I renew my certificates (monthly).

There's two solutions I came across to this problem, the first was to run `certbot renew` with the `--reuse-keys` option, however reusing the same certificates each renewal is not recommended and is far from the best solution to this problem, the second solution was to automate the process of generating new TLSA records along with the renewal of the certificates every month, this project achieves this by using the x509 library in python along with the CloudFlare API library to automatically republish the TLSA certificates directly from my mail server after new certificates have been issues from LE; a far more optimal solution to the original problem.

# How to use

To use this project first clone it and then install the requirements as such:
```bash
python3 -m pip install -r requirements.txt
```

Then update the lines `zone_name` and `cf_api_key` in main.py in order to use the cloudflare api

You can then use this code in a cron job to automatically update your TLSA records with CloudFlare each time you renew your LetsEncrypt certificates as such:
```bash
python3 ~/tlsa-py/main.py /etc/letsencrypt/live/example.com
```

# Using environment variables instead of defining secrets in main.py
If you prefer to use environment variables instead of defining secrets in the main.py file you can easily do this by adding/modifying the following lines in `main.py`

at the top of the file add the following line
```python3
import os
```

then remove the following lines from the file
```python3
zone_name = "example.com"
cf_api_key = "-aPikEyeXamplE"
```

replace the lines you just removed with the following lines
```python3
zone_name = os.environ.get("ZONE_NAME")
cf_api_key = os.environ.get("CF_API_KEY")
```

You can now run the program using the following command via a Cron job or however you with to interact with this code
for example:
```bash
ZONE_NAME=example.com CF_API_KEY="-example" python3 main.py /etc/letsencrypt/live/example.com
```

### Did this help you?

If you like this code and it's helped you out (i hope it has made your job a little less complicated) then please leave a star on the project to help it reach more people, and if you have any suggestions or even know a way to improve this project feel free to open a pull request/issue and I'll be sure to take a look!