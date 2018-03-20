import argparse
import re
import socket
import subprocess
import sys
from urllib.request import urlopen


def get_AS_and_country(ip):
    with socket.socket() as s:
        result = ""
        whois = get_whois(ip)
        if whois == "undefined":
            return "undefined", "undefined"
        s.connect((whois, 43))
        s.send(str.encode(ip) + b"\n")
        while True:
            buffer = s.recv(4096)
            if buffer:
                result = buffer.decode()
            else:
                break
        result = result.lower()

        def parse_AS():
            a = "origin:         "
            ast = result.find(a) + len(a)
            afin = result.find("\n", ast)
            return result[ast:afin] if ast != len(a) - 1 else "undefined"

        def parse_country():
            a = "country:       "
            cst = result.find(a) + len(a)
            cfin = result.find("\n", cst)
            return result[cst:cfin] if cst != len(a) - 1 else "undefined"

        return parse_AS(), parse_country()


def get_ISP(ip):
    with urlopen("https://www.whoismyisp.org/ip/" + ip) as page:
        page = page.read().decode()
        if page.find("No ISP associated") != -1:
            return "undefined"
        a = ">The ISP of "
        ind1 = page.find(a)
        st = page.find("\"isp\">", ind1) + len("\"isp\">")
        fn = page.find("</p>", st)
        return page[st:fn]


def get_whois(ip):
    with urlopen('http://www.iana.org/whois?q=' + ip) as page:
        page = page.read().decode()
        ind1 = page.find("whois:")
        if ind1 == -1:
            return "undefined"
        st = page.find("w", ind1 + 1)
        fn = page.find("\n", st)
        return page[st:fn]


def tracert(domain):
    inp = subprocess.check_output('tracert ' + domain, shell=True)
    lines = inp.decode('cp866').split('\n')[1:]
    addreses = []
    for line in lines:
        try:
            rr = re.search(r"(\d{1,3}\.){3}\d{1,3}", line)
            addreses.append(rr.group(0))
        except Exception:
            continue
    return addreses


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', type=str)
    parser.add_argument('-i', '--ip', type=str)
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])
    adrs = tracert(args.domain) if args.domain is not None else tracert(args.ip)
    for ip in adrs:
        AS, country = get_AS_and_country(ip)
        ISP = get_ISP(ip)
        print("IP: {0}, AS: {1}, Country: {2}, ISP: {3}".format(ip, AS[1:], country, ISP))
# 130.172.121.112 general motors
# 168.135.10.6 deluxe corporation
# 212.193.163.7 e1
# 217.69.134.168 mail
