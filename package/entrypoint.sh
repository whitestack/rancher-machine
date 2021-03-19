#!/bin/sh
set -e
self=$$
termination_log="/dev/termination-log"

for i; do
  shift
  case $i in
    --driver-download-url=*)
      driver_url=${i##--driver-download-url=}
    ;;
    --driver-hash=*)
      driver_hash=${i##--driver-hash=}
    ;;
    *)
      set -- "$@" "$i"
    ;;
  esac
done

if [ -n "$driver_url" ]; then
  echo "Downloading driver from $driver_url" | tee -a $termination_log
  if [ -z "$driver_hash" ]; then
    echo "driver-hash not provided, will not verify after download" | tee -a $termination_log
  fi
  if ! { download_driver.sh "$driver_url" "$driver_hash" 2>&1 || kill $self; } | tee -a $termination_log; then
   echo "download of driver from $driver_url failed" | tee -a $termination_log
   exit 1
  fi
fi

{ rancher-machine $@ 2>&1 || kill $self; } | tee -a $termination_log