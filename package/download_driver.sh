#!/bin/sh

driver_prefix=docker-machine-driver-

curl -sLO "$1"
driver_file=$(ls $driver_prefix*)
driver_name=$(echo "$driver_file" | sed -e "s/^$driver_prefix//" -e "s/[-_\.].*$//")
driver_path=driver_dir/$driver_prefix$driver_name

# Verify the hash of the driver, if it is provided
if [ "$2" ]; then
  if [ "$2  $driver_file" != "$(sha256sum $driver_file)" ]; then
    echo "downloaded file $driver_file failed sha256 checksum"
    exit 1
  fi
fi

mkdir driver_dir

file_type_output=$(file "$driver_file")
echo $driver_file
echo $file_type_output
if echo "$file_type_output" | grep -q "ELF"; then
  driver_path=$driver_file
elif echo "$file_type_output" | grep -q "Zip archive"; then
  if ! unzip -qq -d driver_dir "$driver_file" 2>/dev/null; then
    echo "could not unzip $driver_name"
    exit 1
  fi
elif echo "$file_type_output" | grep -q "gzip compressed"; then
  if ! tar zxf "$driver_file" -C driver_dir 2>/dev/null; then
    echo "could not inflate $driver_name"
    exit 1
  fi
else
  echo "driver file does not seem to be in an accepted format"
  exit 1
fi

chmod +x $driver_path
mv $driver_path /usr/local/bin/$driver_prefix$driver_name
rm -rf driver_dir $driver_file $driver_path