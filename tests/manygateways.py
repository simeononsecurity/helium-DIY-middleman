import argparse
import os
import subprocess

# Create an argument parser for the gateway script
parser = argparse.ArgumentParser("launch gateways2miners.py for each JSON file in a specified folder")
parser.add_argument('-p', '--port', help='port to listen for gateway on', default=1680, type=int)
parser.add_argument('-c', '--configs', help='path where to locate JSON files', default='json_configs/', type=str)
parser.add_argument('-d', '--debug', action='store_true', help="print verbose debug messages")
parser.add_argument('-k', '--keepalive', help='keep alive interval in seconds', default=10, type=int)
parser.add_argument('-s', '--stat', help='stat interval in seconds', default=30, type=int)
parser.add_argument('-t', '--tx-adjust', help='adjust transmit power by some constant (in dB).', type=float, metavar='<adjustment-db>', default=0.0)
parser.add_argument('-r', '--rx-adjust', help='adjust reported receive power by some constant (in dB).', type=float, metavar='<adjustment-db>', default=0.0)

# Parse the arguments
args = parser.parse_args()

# Loop through the JSON files in the folder and launch a gateway for each
for filename in os.listdir(args.configs):
    if filename.endswith(".json"):
        # Construct the command to run
        cmd = f"python gateways2miners.py -p {args.port} -c {os.path.join(args.configs, filename)} -d {'-d' if args.debug else ''} -k {args.keepalive} -s {args.stat} -t {args.tx_adjust} -r {args.rx_adjust}"
        # Launch the gateway as a subprocess
        subprocess.Popen(cmd, shell=True)
