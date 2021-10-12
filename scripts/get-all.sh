#!/bin/sh

rm contents.txt

for i in $(seq 0 1); do
    contents=$(curl "https://donut.caltech.edu/1/users/$i" \
    -H 'Connection: keep-alive' \
    -H 'Pragma: no-cache' \
    -H 'Cache-Control: no-cache' \
    -H 'sec-ch-ua: ";Not A Brand";v="99", "Chromium";v="94"' \
    -H 'sec-ch-ua-mobile: ?0' \
    -H 'sec-ch-ua-platform: "Linux"' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
    -H 'Sec-Fetch-Site: none' \
    -H 'Sec-Fetch-Mode: navigate' \
    -H 'Sec-Fetch-User: ?1' \
    -H 'Sec-Fetch-Dest: document' \
    -H 'Accept-Language: en-US,en;q=0.9,zh-TW;q=0.8,zh-CN;q=0.7,zh;q=0.6' \
    -H 'Cookie: session=eyJ1c2VybmFtZSI6ImRlbGxpb3R0In0.FEZ3gw.Z8KxaD-hIVzGmbo31QyJLnjkdEc' \
    --compressed)

    name=$(echo $contents | sed -n 's,.*<h2 class="pos-left"> \(.*\) </h2>.*,\1,p')
    email=$(echo $contents | sed -n 's/.*mailto:\([^@]\+@caltech.edu\).*/\1/p')
    year=$(echo $contents | sed -n 's,.*<strong>Graduation</strong>: \([0-9]\+\).*,\1,p')

    if [ ! -z "$email" ]; then
        echo -e "$name\t$email\t$year" | tee -a contents.txt
    fi
# \
 #| sed -rn 's/mailto:(.*@caltech.edu)/\1/p' \
done
