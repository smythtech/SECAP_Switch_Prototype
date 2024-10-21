# SECAP Switch Prototype

# Description
This repository contains the P4 code of the SECAP Switch presented in the paper "SECAP switch—Defeating topology poisoning attacks using P4 data planes". This work modifies the ONOS Basic P4 program to include an additional table that learns and verifies layer 2 and layer 3 addresses. This also has the capability to calculate LLDP inter-arrival times that can be collected the processed externally for Link Fabrication Attack (LFA) detection.

This code contains the features described in the paper. It's current state is experimental and this code is not production ready.

# Compiling for ONOS

Before compiling, the secap switch files need to be added to the ONOS source as a new pipeline. 

Compilation follows the same process as the ONOS Basic P4 program. Run "make" in the secap directory. Compile ONOS using "bazel run onos-local -- clean " and the pipeline will now be available to activate through the applications menu. 

# Debugging

The P4 code contains a custom debugging system to allow data to be retrieved from P4 registers through special debug packets. In its current state the data sent in the debug message will be data related to the LFA detection system. This can be modified to extract other values.

Two Python scripts are provided to interact with the debug system. "get_debug.py" will trigger a debug response from the switch, while "parse_debug.py" will listen for debug messages and print them.
