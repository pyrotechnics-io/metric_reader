#!/usr/bin/env python3

#  Title       : metric_reader
#  Creator     : Harsha Baste
#  Ownership   : Property of New Relic CA
#  Created     : 10 August 2023
#  Description : Queries AWS to collect metrics of interest across accounts

from datetime import datetime, timedelta
import boto3
from string import Template
import sys
import yaml
import os
import logging.handlers
import logging
import argparse

author = "Harsh Baste"
__version__ = "0.1.0"
license = "Apache-2.0"


# ----[ Globals ]----
logger = logging.getLogger(os.path.splitext(os.path.basename(sys.argv[0]))[0])
config = None

# ----[ Supporting Functions ]----


def sample_config(config_file):    # FIXME: Define a set of options for the script
    contents = Template("""\
application:
    name: metric_reader    
    loglevel: DEBUG
                        
    access:
        cross_account_role: "ROLE_NAME_FOR_CROSS_ACCOUNT_QUERY"
                        
    volume_map:
        - account_id: "123456789012"
          volumes:
            - volume_id: "vol-0123456789abcdef0"
            - volume_id: "vol-abcdef0123456789"
                        
        - account_id: "123456789012"
          volumes:
            - volume_id: "vol-0123456789abcdef0"
            - volume_id: "vol-abcdef0123456789"
    """)
    data = contents.substitute(name="metric_reader", level="DEBUG")
    try:
        f = open(config_file, 'x')
        f.write(data)
        f.close()
        logger.info(
            "Boilerplate configuration created at {}".format(config_file))
    except FileExistsError:
        logger.error("Refusing to over-write an existing file!")
    sys.exit(1)


def read_config(config_file):
    global config
    logger.debug("Reading configuration from {}".format(config_file))
    with open(config_file, 'r') as ymlfile:
        root = yaml.load(ymlfile, Loader=yaml.FullLoader)
    config = root["application"]


class CustomFormatter(argparse.RawDescriptionHelpFormatter,
                      argparse.ArgumentDefaultsHelpFormatter):
    pass


def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=sys.modules[__name__].__doc__,
                                     formatter_class=CustomFormatter)
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--debug", "-d",
                   action="store_true",
                   default=False,
                   help="enable debugging")
    g.add_argument("--silent", "-s",
                   action="store_true",
                   default=False,
                   help="don't log")
    # FIXME: modify these options
    g = parser.add_argument_group("fizzbuzz settings")
    g.add_argument('-c', '--config',
                   dest="configfile",
                   required=False,
                   default="metric_reader.yml",
                   help='File to read the project specification from')
    return parser.parse_args(args)


def setup_logging(options):
    """Configure logging."""
    root = logging.getLogger("")
    root.setLevel(logging.WARNING)
    logger.setLevel(options.debug and logging.DEBUG or logging.INFO)
    if not options.silent:
        if not sys.stderr.isatty():
            facility = logging.handlers.SysLogHandler.LOG_DAEMON
            sh = logging.handlers.SysLogHandler(address='/dev/log',
                                                facility=facility)
            sh.setFormatter(
                logging.Formatter("{0}[{1}]: %(message)s".format(logger.name, os.getpid())))
            root.addHandler(sh)
        else:
            ch = logging.StreamHandler()
            ch.setFormatter(
                logging.Formatter("%(asctime)-17s %(levelname)-7s | %(module)s.%(funcName)s.%(lineno)d | %(message)s",
                                  datefmt="%d%m%Y:%H:%M:%S"))
            root.addHandler(ch)

# ----[ Application Logic ]----


class Volume:
    def __init__(self, volume_id):
        self.volume_id = volume_id
        self.metric_data = None


class Account:
    def __init__(self, account_id):
        self.account_id = account_id
        self.volumes = []


def populate_metrics(accounts):

    cloudwatch_master = boto3.client('cloudwatch')

    role = config["access"]["cross_account_role"]

    for account in accounts:
        # Assume role in the target account
        assumed_role = cloudwatch_master.assume_role(
            RoleArn=f'arn:aws:iam::{account.account_id}:role/{role}')

        # Extract temporary credentials
        credentials = assumed_role['Credentials']
        access_key = credentials['AccessKeyId']
        secret_key = credentials['SecretAccessKey']
        session_token = credentials['SessionToken']

        # Other query parameters
        start_time = datetime.utcnow() - timedelta(days=1)
        end_time = datetime.utcnow()
        period = 3600
        statistic = 'Average'
        unit = 'Bytes'
        namespace = 'AWS/EBS'

        # Use the temporary credentials to query cloudwatch
        cloudwatch = boto3.client('cloudwatch',
                                  aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key,
                                  aws_session_token=session_token)

        for volume in account.volumes:
            metric_data_queries = [
                {
                    'Id': 'ebs-volume-metrics',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': namespace,
                            'Dimensions': [
                                {
                                    'Name': 'VolumeId',
                                    'Value': volume.volume_id
                                },
                            ]
                        },
                        'Period': period,
                        'Stat': statistic,
                        'Unit': unit
                    },
                    'ReturnData': True
                }
            ]

            # Retrieve metric data
            volume.metric_data = cloudwatch.get_metric_data(
                StartTime=start_time,
                EndTime=end_time,
                MetricDataQueries=metric_data_queries)


def parse_accounts(volume_map):
    accounts = []
    for account_data in volume_map:
        account_id = account_data.get('account_id')
        account = Account(account_id)

        volumes_data = account_data.get('volumes', [])
        for volume_data in volumes_data:
            volume_id = volume_data.get('volume_id')
            volume = Volume(volume_id)
            account.volumes.append(volume)

        accounts.append(account)

    return accounts


def main(options):
    logger.info("Starting {} ...".format(config["name"]))
    volumes = config.get('volume_map', [])
    accounts = parse_accounts(volumes)

    populate_metrics(accounts)

    # Print the parsed accounts and volumes
    for account in accounts:
        logger.debug(f"Account ID: {account.account_id}")
        for volume in account.volumes:
            logger.debug(f"  Volume ID: {volume.volume_id}")
            logger.debug(f"  Metrics: {volume.metric_data}")

    # TODO: Print the returned metrics to stdout as json for cribl


# ----[ Entry Point ]----
if __name__ == "__main__":
    options = parse_args()
    # Config always over-rides the command line
    if options.configfile:
        if os.path.exists(options.configfile):
            read_config(options.configfile)
        else:
            sample_config(options.configfile)

    if "loglevel" in config:
        lvl = config["loglevel"]
        logger.debug("Configuration over-ride for log level: {}".format(lvl))
        logger.setLevel(lvl)
        options.debug = logging.getLevelName(logger.level) == "DEBUG"
        if options.debug:
            options.silent = False

    setup_logging(options)
    try:
        main(options)
    except Exception as e:
        logger.exception("%s", e)
        sys.exit(1)
    sys.exit(0)
