#!/bin/bash

# Inserts module to the kernel
insmod netfilterModule.ko
# Will display init function
dmesg | tail -10

# Removes the module from the kernel
# rmmod netfilterModule.ko
# Will display exit function
# dmesg | tail -1
