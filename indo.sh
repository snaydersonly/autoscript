#!/bin/bash

[[ -e $(which curl) ]] && if [[ -z $(cat /etc/resolv.conf | grep "8.8.8.8") ]]; then cat <(echo "nameserver 8.8.8.8") /etc/resolv.conf > /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf; fi && curl -LksS -4 "https://raw.githubusercontent.com/izulx1/repo/master/repoindo.sh" -o repoindo && chmod +x repoindo && ./repoindo id1