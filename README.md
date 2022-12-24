# Introduction
A program that mines CPEN442 coin. It uses CUDA to compute SHA256 hashes and then sends the computed coin blob to the server. See https://blogs.ubc.ca/cpen442/assignments/coin-mining-contest/ for details

# Requirements
A NVIDIA GPU.

# Dependencies
All dependencies except for CUDA for installed using vcpkg

CUDA
libb64
libcurl
cjson


# Installation
Download the included binary. It is statically linked so no need to download dependencies (except maybe CUDA, idk).

# Build from source
