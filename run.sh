#!/usr/bin/env bash

# Syntax: ./run.sh [ip address or domain name]
#

# initialize ip_addr variable to localhost
# CHANGE THIS TO YOUR OWN IP ADDRESS TO START
# THE SERVER WITHOUT PROVIDING YOUR DOMAIN
# OVER AND OVER AGAIN
IP_ADDR="127.0.0.1"
PORT="8000"
SERVER_PATH="$PWD/server"
SESSION="shellmap_server"
CONNECT_SESSION="y"

case "$#" in
	0)
		if which dig 2>/dev/null >/dev/null; then
			echo "Looking up public IP address using dig..."
			ip_addr=$(dig myip.opendns.com @resolver1.opendns.com +short | grep -v ";;")
			echo "Public IP address found: $IP_ADDR"
		else
			echo "Please install dig or provide a public IP address"
			exit
		fi
		;;
	1)
		if [ "$1" = "--help" ]; then
			echo "Syntax: ./run.sh [ip address or domain name]"
			exit
		else
			IP_ADDR="$1"
		fi
		;;
	2)
		IP_ADDR="$1"
		if [ "$2" =~ [1-9][0-9]* ]; then
			PORT="$2"
		else
			echo "Port invalid, using default ${PORT}"
		fi
		;;
	*)
		echo "Syntax: ./run.sh [ip address or domain name]"
		exit
		;;
esac

if which tmux 2>&1 1>/dev/null; then
	tmux has-session -t $SESSION 2>/dev/null
	if [ $? != 0 ]; then
		tmux new -d -c "$SERVER_PATH" -s $SESSION
		echo "Created new tmux session 'shellmap_server'"
		echo "View the execution of the server with 'tmux attach-session -t shellmap_server'"
		echo "Starting ShellMap server..."
		tmux send-keys -t shellmap_server "python3 ./server.py ${IP_ADDR} ${PORT}" C-m
	fi
	if [ $CONNECTION_SESSION = "y" ]; then
		tmux attach-session -t $SESSION
	fi
else
	echo "Please install tmux"
	exit
fi

