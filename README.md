## What is this repo?

This repo contains the oracle server that helps enforce 3 PIN tentatives on [Jade](https://github.com/Blockstream/Jade).

The oracle is blind to the pin and should be easy to run an instance of the
server over Tor.

In the future we plan to use the pin server in other projects such as Blockstream
Green.

## To generate a new key

`python -m venv venv`

`. venv/bin/activate`

`pip install --require-hashes -r requirements.txt`

`PYTHONPATH=.. python -m blind_pin_server.generateserverkey`

## Securing the server key

Anyone who can read `server_private_key.key` can impersonate this server, so it is created
mode `0600` and the server refuses to start if it is readable by anyone else.

In the container it is read by `www-data`:

`sudo chown www-data:www-data server_private_key.key`

`sudo chmod 600 server_private_key.key`

Mount it read-only (`:ro`, as below) so the container can't alter it.

## Build the docker image

`docker build -f Dockerfile . -t dockerized_pinserver`

## Prepare the directory for all the pins

`mkdir pinsdir`

## Run the docker image (requires the previous steps)

`docker run -v $PWD/server_private_key.key:/server_private_key.key:ro -v $PWD/pinsdir:/pins -p 8096:8096 dockerized_pinserver`
