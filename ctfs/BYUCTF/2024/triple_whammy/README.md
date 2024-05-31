# BYU CTF 2024 - Triple Whammy

**Summary**: Exploit the XSS vulnerability on a page of the website and have the admin bot visit it with a payload that will have the admin bot bruteforce all possible ports for an insecure pickle deserialization service, and have the admin bot send the pickle exploit payload to this service to leak the flag

The `main()` function in `server.py` has an xss in the `name` field, which can be passed with a `GET` parameter. Our eventual goal is to have the admin bot send `POST` requests to the `/query` path of `server.py`. We cannot do this ourselves because of the unknown value in `secret.txt`, and the admin bot only accepts `GET` requests. What we need to do here is to have the admin bot visit the page with the XSS, and then specify an XSS payload that will perform the POST requests for us. There is a pickle service (`internal.py`) running on a random port between 5700 and 6000 on the server, and we can write an xss payload that will bruteforce this port number and sent a pickle exploit to leak the flag to all of those ports.

