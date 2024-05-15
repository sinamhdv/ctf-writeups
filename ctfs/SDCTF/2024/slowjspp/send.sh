#!/bin/bash
# script to send exploit file to the server

if [ $# -ne 1 ]; then
	echo "Usage: ./send.sh <exploit file>"
	exit 1
fi

(cat $1 ; echo -e '\nEOF' ; cat) | ./websocat wss://ctf.sdc.tf/api/proxy/a34a6028-9d38-44b8-998a-b7a1dc0a6b33
