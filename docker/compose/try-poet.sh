#!/bin/bash

#sudo rm -rf ../../build
docker-compose -f docker-compose-sgx-hw.yaml down
docker-compose -f docker-compose-sgx-hw.yaml up
