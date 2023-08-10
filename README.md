# Metric Reader

This script is used to fetch metrics from AWS. 

It has been built to fetch EBS metrics but can be trivially extended to pull anything CloudWatch has on offer.

## Requirements

This script assumes you have an AWS CLI configured on the login where this script will be launched from. 

Additionally, on the assumption that this code needs to handle multiple accounts and EBS volumes under them, it also requires a cross account role that allows it to query CloudWatch for this data using AssumeRole. 

# Usage 

- Install requirements
- Launch the script without any parameters first. This will create a sample configuration file (also checked into this repository for reference)
- Launch the script giving it the configuration file for normal operation
```cli
./metric_reader.py -c metric_reader.yml
```

This will read through the config with the supplied account and volume data, query AWS for each and print the results to STDOUT. 

The output may be sent to other ETL pipelines for ingest. 
