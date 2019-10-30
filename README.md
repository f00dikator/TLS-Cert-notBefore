# TLS-Cert-notBefore
First GoLang program. Very simple program. 

1) Sniff traffic off the wire and determine if it is TLS/SSL
2) If it's TLS, determine if we have a 'Server Cert' response from server (type 0x0b)
3) If it's TLS and has a Server Cert, parse out the notBefore time (e.g. when the cert was created)
4) Log out the notBefore time as well as the src and dst IP

Note: this was a bad idea. A lot of free TLS certs are newly created. 
