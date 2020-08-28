httpie-cbw-api-auth
===================

CyberWatch [APIAuth](https://github.com/mgomes/api_auth) Plugin for [HTTPie]( http://httpie.org). Inspired by [httpie-api-auth](https://github.com/pd/httpie-api-auth)

Installation
------------

    sudo apt-get install httpie
    git clone https://github.com/Cyberwatch/httpie-cbw-api-auth.git
    cd ./httpie-cbw-api-auth
    sudo python3 setup.py install

Usage
-----

    http --auth-type=cbw-api-auth --auth='ACCESS_KEY_ID:SECRET_ACCESS_KEY' localhost:3000/api/v3/ping

Documentation
-------------

See the full API documentation [here](https://docs.cyberwatch.fr/)

Compatibility
-------------

Only compatible with _CyberWatch APIAuth HMAC-SHA256_
