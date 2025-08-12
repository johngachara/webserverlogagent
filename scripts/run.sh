#!/bin/bash
if [ -z "$1" ]; then
  echo "Please enter the image tag to be deployed"
  exit 1  # optionally stop the script here
fi
echo "Starting log agent"
sudo docker run --name logagent --env-file .env --network host --privileged -d -v ./config.yaml:/logagent/config.yaml:ro -v /var/log:/var/log:ro gachar4/logagent:"$1"
echo "Successfully started the agent"
