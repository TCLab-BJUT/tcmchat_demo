#!/bin/bash
cd monitor
ln -s $CUBESYSPATH/main/main_proc
cd -
cd crypto_hub
ln -s $CUBESYSPATH/main/main_proc
mkdir cert pubkey privkey
cd -
cd server
ln -s $CUBESYSPATH/main/main_proc
cd -
cd backend
ln -s $CUBESYSPATH/main/main_proc
cd -
cd module
make 
cd -
