while getopts "dhsr" opt; do
    case $opt in 
			d)
			iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5353
			iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5353
			echo "tcp 53 => 5353"
			echo "udp 53 => 5353" ;;
			h)
			iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8080
			echo "tcp 80 => 8080" ;;
			s)
			iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8443
			echo "tcp 443 => 8443" ;;
			r)
			iptables -t nat -F
			echo "reset iptables" ;;
    esac    
done

#iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 5555
#iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports 5556
#iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports 5557
