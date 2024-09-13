# certbot_proxy
This go program is made for handling Letsencrypt/Certbot on internal servers.

certbot_proxy is installed on a reverse proxy server (eg. Nginx) facing the Internet.
The certbot_proxy is handling the calls to http://<_FQDN_>/.well-known/acme-challenge/<_token_> from the certificat provider

And it is also handling POST / DELETE of token data from the certbot client, using curl in the certbot_auth_hook
and certbot_cleanup_hook scripts.

certbot_auth_hook script example:
```bash
#!/bin/bash

curl -H "application/json" -d "{\"domain\": \"$CERTBOT_DOMAIN\", \"token\": \"$CERTBOT_TOKEN\", \"validation\": \"$CERTBOT_VALIDATION\"}" https://certbot-proxy.your-own-domain.org/token_poster/
```

certbot_cleanup_hook script example:
```bash
#!/bin/bash

curl -X DELETE -H "application/json" -d "{\"domain\": \"$CERTBOT_DOMAIN\"}" https://certbot-proxy.your-own-domain.org/token_poster/
```

The /token_poster/ URL should be rewritten to a long random URL and be placed behind a TLS site.

Remeber to add a *.<FQDN> in the external DNS pointing to the Nginx server where certbot_proxy is behind.

The certbot_proxy can also be used to upload files to the certbot_proxy server. Eg:
```bash
curl -F "domain=network-it.dk" -F "file=@filechain.pem" -F "file=key.pem" https://certbot-proxy.your-own-domain.org/token_poster/upload
```

## Configuration example for certbot_proxy server
The example is based on setup on Ubuntu Server 20.04
### OS / system settings
#### Add user for certbot_proxy
```
# Add certbot_proxy systemuser
sudo adduser --system --group --shell /usr/bin/nologin --home /opt/certbot_proxy --disabled-login certbot_proxy

sudo mkdir -p /opt/certbot_proxy/upload
sudo chown certbot_proxy:certbot_proxy /opt/certbot_proxy/upload
sudo chown root:certbot_proxy /opt/certbot_proxy
sudo chmod -R 750 /opt/certbot_proxy
```

#### Copy the certbot_proxy program to /opt/certbot_proxy
```bash
cd /opt/certbot_proxy
sudo wget https://....
# shasum should match ...
sudo shasum certbot_proxy
sudo chown root:certbot_proxy certbot_proxy
sudo chmod 510 certbot_proxy
```

#### Setup systemd service
Create /etc/systemd/system/certbot_proxy.service with following content:
```
[Unit]
Description=Certbot proxy for handling internal cert requests
After=network.target auditd.service

[Service]
User=certbot_proxy
EnvironmentFile=-/etc/default/certbot_proxy
ExecStart=/opt/certbot_proxy/certbot_proxy
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=simple
RuntimeDirectory=certbot_proxy
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=certbox_proxy.service
```

Create /etc/default/certbot_proxy with content like:
```systemd
# Default port for Certbot Proxy
PORT=4080

# Default token post path
#TOKEN_POST_PATH="/token_poster/"
# But token path should be more unredict able and should match the path in the Nginx config
TOKEN_POST_PATH="/ShouldBeChangedIntoALongRandomStringWithoutSpaces/"

# Default upload path is the program folder with /upload added
#UPLOAD_PATH="/SomethingElse"
```

### Nginx example
/etc/nginx/sites-enabled/default linked to /etc/nginx/sites-available/default containing:
```
# This is for serving .well-known/acme-challenge/
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        server_name _;

        location / {
                return 404;
        }

        location /.well-known/acme-challenge/ {
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header Host $http_host;
                proxy_pass http://127.0.0.1:4080;
        }
}
```

/etc/nginx/sites-enabled/main-site-ssl linked to /etc/nginx/sites-available/main-site-ssl containing something like:
```
        # SSL configuration
        #
        listen 443 ssl;
        listen [::]:443 ssl;
        
        include snippets/cert-setup.conf;
        
        root /var/www/html;
        index index.html index.htm;

        server_name certbot-proxy.your-own-domain.org;
        
        include snippets/error-pages.conf;
        
        location / {
                try_files $uri $uri/ =404;
        }

        location /ShouldBeChangedIntoALongRandomStringWithoutSpaces/ {
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header Host $http_host;
                proxy_pass http://127.0.0.1:4080;
        }

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        location ~ /\.ht {
                deny all;
        }
}
```

## Compile certbot_proxy
For Ubuntu amd64:
```
GOOS=linux GOARCH=amd64 go build
```
