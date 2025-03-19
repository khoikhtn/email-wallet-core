#!/bin/bash

curl https://sh.rustup.rs -sSf | sh

curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
  |  tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
  |  tee /etc/apt/sources.list.d/ngrok.list \
  &&  apt update \
  &&  apt install ngrok

ngrok config add-authtoken 2s2IEIbrh2iVhKEFMXRaWsqTbyY_5oQ6uGeyTnkkoSoJDjT4h
ngrok http 3000

