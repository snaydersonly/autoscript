#!/bin/bash
rm -f $0

rm -f /etc/cron.d/daily_backup

cat >/etc/cron.d/daily_backup <<-END
*/59 * * * * root /usr/local/bin/daily_backup
END

service cron restart
service cron reload
systemctl restart cron

wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
