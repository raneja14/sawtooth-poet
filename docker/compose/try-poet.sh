#!/bin/bash

sudo rm -rf ../../build
docker-compose -f docker-compose-sgx-hw.yaml down -v
docker-compose -f docker-compose-sgx-hw.yaml up
