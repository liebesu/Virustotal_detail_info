#!/bin/bash


while :
do
  if [[ $(ps -ef | grep get_pe_info.py | grep -v grep) ]];then
    continue
  else
    sleep 60
    echo "start .py"
    python get_pe_info.py
  fi
  sleep 1
done

