#!/bin/bash
set -x -e

wget -c https://github.com/ontio/ontology/releases/download/v2.3.5/ontology-linux-amd64 -O ontology
chmod +x ontology
echo -e "123456\n123456\n" | ./ontology account add -d
echo -e "123456\n" | nohup  ./ontology --testmode --testmode-gen-block-time 10 > /dev/null 2>&1 &
# wait test ontology ready
sleep 10

go mod tidy
go build
go test -v ./...

pkill ontology || true
