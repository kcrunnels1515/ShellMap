#!/usr/bin/env bash

# Syntax: ./run.sh [ip address]
#

# initialize ip_addr variable to localhost
ip_addr="127.0.0.1"
server_path="$PWD/server"
if [ "$#" -lt 1 ]; then
	if which dig 2>/dev/null >/dev/null; then
		echo "Looking up public IP address using dig..."
		ip_addr=$(dig myip.opendns.com @resolver1.opendns.com +short | grep -v ";;")
		echo "Public IP address found: $ip_addr"
	else
		echo "Please install dig or provide a public IP address"
		exit
	fi
elif [ "$1" = "--help" ]; then
	echo "Syntax: ./run.sh [ip address]"
	exit
elif [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "Validated IP address: $1"
	ip_addr="$1"
else
	echo "Syntax: ./run.sh [ip address]"
	exit
fi

if which tmux 2>&1 1>/dev/null; then
	tmux new -d -c "$server_path" -s shellmap_server
	echo "Created new tmux session 'shellmap_server'"
	echo "View the execution of the server with 'tmux attach-session -t shellmap_server'"
	echo "Starting ShellMap server..."
	tmux send-keys -t shellmap_server 'python3 ./server.py' C-m
	exit
else
	echo "Please install tmux"
	exit
fi

