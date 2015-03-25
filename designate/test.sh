#!/bin/sh -e

curl -H 'content-type: application/json' -k -X POST -d '{"name": "ns1.example.org."}' http://localhost:9001/v1/servers

curl -H 'content-type: application/json' -k -X POST -d '{"email": "admin@example.org", "name": "example.org.", "ttl": 3600}' http://localhost:9001/v1/domains

id=$(curl http://localhost:9001/v1/domains | jq '.domains[0].id' | awk -F\" '{print $2}')
echo $id

curl -X POST -H 'content-type: application/json' -d '{"name": "www.example.org.", "type": "A", "data": "192.0.2.3"}' http://localhost:9001/v1/domains/${id}/records
