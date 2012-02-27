#!/usr/bin/python

import datetime
import urllib2
import socket
import ssl
import re
import pprint

#========================================================================
# You will need to change these as needed
#
DtDNS_domain="yourdomain.dtdns.net"
DtDNS_passwd="yourpassword"
#
#========================================================================
remote = 'www.dtdns.com'
port = 443
certs_file = '/etc/ssl/certs/ca-certificates.crt'
#========================================================================

def get_request_server(msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # require a certificate from the server
    ssl_sock = ssl.wrap_socket(s,
                               ca_certs=certs_file,
                               cert_reqs=ssl.CERT_REQUIRED)
    
    ssl_sock.connect((remote, port))
    
    cert = ssl_sock.getpeercert()
    if not cert or ('commonName', u'www.dtdns.com') not in cert['subject'][2]:
        raise Exception('InvaliCert')

    # Set a simple HTTP request -- use httplib in actual code.
    ssl_sock.write(msg)
    
    # read all the data returned by the server.
    next = "1"
    data = []
    while next:
        next = ssl_sock.read()
        data.append(next)
    
    # note that closing the SSLSocket will also close the underlying socket
    ssl_sock.close()
    
    return ''.join(data)

def get_dns_ip():
    msg_get_ip="GET /api/autodns.cfm?id=%s&pw=%s HTTP/1.1\nHost: www.dtdns.com\nUser-Agent: Hugheshut-ssl\n\n" % (DtDNS_domain, DtDNS_passwd)
    data = get_request_server(msg_get_ip)
    
    reg = re.compile(".*Host (.*) now points to ([0-9\.]+[0-9]+).*", re.DOTALL)
    result = reg.match(data)
    if result:
        host = result.group(1)
        ip = result.group(2)
        return ip
    else:
        return None

def set_dns_ip(ip):
    msg_set_ip="GET /api/autodns.cfm?id=%s&pw=%s&ip=%s HTTP/1.1\nHost: www.dtdns.com\nUser-Agent: Hugheshut-ssl\n\n" % (DtDNS_domain, DtDNS_passwd, ip)
    get_request_server(msg_set_ip)

def get_ext_ip():
    f = urllib2.urlopen('http://whatismyip.org/')
    return f.read()

def main():
    print str(datetime.datetime.now())
    dns_ip = get_dns_ip()
    print "dns ip : %s" % dns_ip
    ext_ip = get_ext_ip()
    print "ext ip : %s" % ext_ip

    if dns_ip != ext_ip:
        print "KO : It differs ! :("
        set_dns_ip(ext_ip)
    else:
        print "OK : It's all good ! :)"

    print ""
    
if __name__ == '__main__':
    main()
