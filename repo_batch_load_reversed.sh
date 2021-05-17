#!/bin/bash
# set -xv
# echo $#
if [[ "$#" -ne 8 ]];
then
  echo "Exactly 7 arguments are required"
  echo "[path]       - path to repository storage root"
  echo "[name]       - name of repository to be loaded"
  echo "[tag]        - path to repository storage root"
  echo "[host]       - DB host address"
  echo "[database]   - DB name"
  echo "[workers]    - number of workers"
  echo "[start_date] - start date in YYYY-MM-DD format"
  echo "[end_date]   - end date in YYYY-MM-DD format"
  exit 1
else

  root_path=$1
  repo_name=$2
  repo_tag=$3
  db_host=$4
  db_base=$5
  extract_workers=$6
  s_date=$7
  e_date=$8

  echo "$(date)" "Start batch repository uploading for" "$repo_name" "to" "$db_base" "database"
  t_start_total=$(date  +%s)
  d=$e_date
  until [[ $d < $s_date ]]; do
    c_year="${d%%-*}"
    tmp="${d#*-}"
    c_month="${tmp%-*}"
    c_day="${tmp#*-}"
    # echo $d, $c_year/$c_month/$c_day
    c_dir=$root_path/$c_year/$c_month/$c_day
    if [[ -d $c_dir ]];
    then
      echo "Processing" "$c_dir"
      t_start=$(date  +%s)
      python3 extract.py "$repo_name" "$c_dir" --date "$d" -s "$db_host" -d "$db_base" -w "$extract_workers" --tag "$repo_tag" -T -v
      t_end=$(date  +%s)
      t_runtime=$((t_end-t_start))
      echo "Time elapsed" $t_runtime "seconds"
      if grep -q -R "Traceback" ./extract-$repo_name-$d.log*; then
        echo "Exception occured during repository load. Sorry"
        exit 1
      fi
    #   echo "It is directory", $c_dir
    # else
    #   echo "It is not directory", $c_dir
    fi
    # increment date
    d=$(date -I -d "$d - 1 day")
  done
  t_end_total=$(date  +%s)
  t_runtime_total=$((t_end_total-t_start_total))
  echo "$(date)" "Batch load finished within" $t_runtime_total "seconds"
fi
