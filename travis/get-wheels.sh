#!/bin/bash

aws s3 cp s3://pycryptodome-releases . --include="*.whl" --recursive
