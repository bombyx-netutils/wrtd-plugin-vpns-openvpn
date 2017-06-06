#!/bin/bash

LIBFILES="$(find ./vpns_openvpn -name '*.py' | tr '\n' ' ')"

autopep8 -ia --ignore=E501 ${LIBFILES}
