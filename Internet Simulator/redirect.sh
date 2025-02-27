#iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 5555
#iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports 5556
#iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports 5557
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8080
#iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8443
#iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5353
#iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5353
