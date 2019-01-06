#!/usr/bin/env bash

dns_container_hostname='dns'

dns_domain='ciab.test'
dns_search_domains='infra.ciab.test ciab.test'

dnsip="$(dig +short ${dns_container_hostname})"

while [ -z $dnsip ]; do
	printf "Waiting for dns container \"${dns_container_hostname}\" to appear in Docker default dns...\n"
	sleep 1
	dnsip="$(dig +short ${dns_container_hostname})"
done

cat << EOF > /etc/resolv.conf
# autogenerated by set-dns.sh
domain ${dns_domain}
search ${dns_search_domains}
nameserver ${dnsip}
EOF
