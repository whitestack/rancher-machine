#!/bin/sh
set -e
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
      # Breaking up arguments that are passed to rancher-machine allows for handling values with spaces.
      flag=${i%%=*}
      value=${i#--*=}
      if [ "$flag" = "$value" ]; then
        # If flag and value are the same, then the argument that was passed doesn't have an equal-sign and can be passed as-is.
        set -- "$@" "$flag"
      else
        set -- "$@" "$flag" "$value"
      fi
    ;;
  esac
done

if [ -n "$driver_url" ]; then
  echo "Downloading driver from $driver_url" | tee -a $termination_log
  if [ -z "$driver_hash" ]; then
    echo "driver-hash not provided, will not verify after download" | tee -a $termination_log
  fi
  if ! { { { { download_driver.sh "$driver_url" "$driver_hash" 2>&1; echo $? >&3; } | tee -a $termination_log >&4; } 3>&1; } | { read xs; exit $xs; } } 4>&1; then
   echo "download of driver from $driver_url failed" | tee -a $termination_log
   exit 1
  fi
fi

{ { { { rancher-machine "$@" 2>&1; echo $? >&3; } | tee -a $termination_log >&4; } 3>&1; } | { read xs; exit $xs; } } 4>&1
