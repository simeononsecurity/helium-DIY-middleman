#!/usr/bin/env python 

import argparse
import os
import json
import logging
import time
import socket
import copy
from hashlib import md5

from src import messages
from src.vgateway import VirtualGateway

class GW2Miner:
    def __init__(self, port, vminer_configs_paths, keepalive_interval=10, stat_interval=30, debug=True, tx_power_adjustment=0.0, rx_power_adjustment=0.0):
        """
        This is the constructor of the GW2Miner class. It initializes the class variables and loads the virtual gateway configurations.

        :param port: The port number to use for the virtual miner.
        :param vminer_configs_paths: A list of paths to the virtual miner configuration files.
        :param keepalive_interval: The interval at which to send keepalive messages to the virtual gateway.
        :param stat_interval: The interval at which to update statistics.
        :param debug: A flag indicating whether to enable debug logging.
        :param tx_power_adjustment: The adjustment to apply to the transmission power.
        :param rx_power_adjustment: The adjustment to apply to the reception power.
        """
        # Initialize the logger for virtual gateways
        self.vgw_logger = logging.getLogger('VGW')
        # Initialize the logger for the virtual miner
        self.vminer_logger = logging.getLogger('VMiner')
        # Store the transmission power adjustment
        self.tx_power_adjustment = tx_power_adjustment
        # Store the reception power adjustment
        self.rx_power_adjustment = rx_power_adjustment

        # Load the virtual gateways configurations
        # ========================================
        # Initialize dictionaries to store virtual gateways by address and by MAC address
        self.vgateways_by_addr = dict()
        self.vgateways_by_mac = dict()
        # Loop over all the virtual miner configuration files
        for path in vminer_configs_paths:
            # Open the configuration file
            with open(path, 'r') as fd:
                config = json.load(fd)
                # Check if the required parameters are present in the configuration file
                if 'gateway_conf' in config:
                    config = config['gateway_conf']
                mac = ''
                if 'gateway_ID' not in config or 'server_address' not in config:
                    self.vgw_logger.error(f"invalid config file {path}, missing required parameters")
                    continue
                # Try to resolve the server address
                try:
                    server_ip = socket.gethostbyname(config.get('server_address'))
                except socket.gaierror:
                    self.vgw_logger.error(f"invalid server_address \"{config.get('server_address')}\" in config {path}")
                    continue
                # Generate the MAC address from the gateway ID
                for i in range(0, len(config.get('gateway_ID')), 2):
                    mac += config.get('gateway_ID')[i:i+2] + ':'
                mac = mac[:-1].upper()

        # Create a VirtualGateway object
        vgw = VirtualGateway(
            mac=mac,
            server_address=server_ip,
            port_dn=config.get('serv_port_down'),
            port_up=config.get('serv_port_up'),
            rx_power_adjustment=rx_power_adjustment
        )
        # Store the virtual gateway in the dictionary of virtual gateways by MAC address
        self.vgateways_by_mac[mac] = vgw
        # Store the virtual gateway in the dictionary of virtual gateways by address
        self.vgateways_by_addr[(server_ip, config.get('serv_port_down'))] = vgw
        self.vgateways_by_addr[(server_ip, config.get('serv_port_up'))] = vgw
        # Log the addition of the virtual gateway
        self.vgw_logger.info(f"added vgateway for miner at {server_ip} port: {config.get('serv_port_up')}(up)/{config.get('serv_port_down')}(dn)")

        # Start the listening socket
        # =========================
        # Create a UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind the socket to the specified port and all available IP addresses
        self.sock.bind(("0.0.0.0", port))
        # Log the start of the listening socket
        logging.info(f"listening on port {port}")

        # Setup other class variables
        # ==========================
        # Initialize a cache for received packets
        self.rxpk_cache = dict()
        # Initialize a dictionary to store the listening addresses of the gateways
        self.gw_listening_addrs = dict() # keys = MAC, values = (ip, port) tuple
        # Store the keepalive interval
        self.keepalive_interval = keepalive_interval
        # Store the statistics interval
        self.stat_interval = stat_interval
        # Initialize the timestamp of the last statistics update
        self.last_stat_ts = 0
        # Initialize the timestamp of the last keepalive message
        self.last_keepalive_ts = 0


    def __rxpk_key__(self, rxpk):
        """
        This method generates a unique key for a received packet (rxpk).
        The key is based on the spreading factor, coding rate, frequency, size, and data of the packet.
        For data larger than 40 characters, the key is based on the MD5 hash of the data.

        :param rxpk: A dictionary representing the received packet.
        :return: A tuple representing the key for the received packet.
        """
        # Create an MD5 hash object
        hash = md5()
        # Update the hash with the encoded data of the received packet
        hash.update(rxpk['data'].encode())
        # Generate the key based on the specified parameters
        key = (
            rxpk['datr'],
            rxpk['codr'],
            str(round(rxpk['freq'], 2)),
            rxpk['size'],
            rxpk['data'] if len(rxpk['data']) < 40 else hash.hexdigest()
        )
        # Return the generated key
        return key


    def run(self):
        """
        This method contains the main loop of the GW2Miner program. It runs indefinitely,
        and it performs the following tasks:
        - Send a keepalive message if the keepalive interval has elapsed.
        - Send statistics if the statistics interval has elapsed.
        - Receive a message from the socket and handle it based on its type.

        :return: None
        """
        # Store the starting timestamp
        start_ts = time.time()
        # Start the infinite loop
        while True:
            # If the time since the last keepalive message is greater than the keepalive interval, send a keepalive message
            if time.time() - self.last_keepalive_ts > self.keepalive_interval:
                self.send_keepalive()
            # If the time since the last statistics update is greater than the statistics interval, send statistics
            if time.time() - self.last_stat_ts > self.stat_interval:
                self.send_stats()

            # Receive a message from the socket
            msg, addr = self.get_message(timeout=5)
            # Update the start timestamp
            start_ts = time.time()
            # If no message was received, continue the loop
            if not msg:
                continue

            # Handle the received message based on its type
            if msg['_NAME_'] == messages.MsgPushData.NAME:
                self.handle_PUSH_DATA(msg, addr)
            elif msg['_NAME_'] == messages.MsgPullResp.NAME:
                self.handle_PULL_RESP(msg, addr)
            elif msg['_NAME_'] == messages.MsgPullData.NAME:
                self.handle_PULL_DATA(msg, addr)
            elif msg['_NAME_'] == messages.MsgTxAck.NAME:
                self.handle_TX_ACK(msg, addr)
            elif msg['_NAME_'] == messages.MsgPushAck.NAME:
                self.handle_PUSH_ACK(msg, addr)
            elif msg['_NAME_'] == messages.MsgPullAck.NAME:
                self.handle_PULL_ACK(msg, addr)

    def handle_PUSH_DATA(self, msg, addr=None):
        """
        This method handles PUSH_DATA messages received from real gateways.
        It de-duplicates the received packets and forwards them to all miners.
        The metadata of the packets can be potentially modified before forwarding.

        :param msg: The PUSH_DATA message received from a real gateway.
        :param addr: The address of the real gateway that sent the message.
        :return: None
        """
        # If the message does not contain received packets (rxpk), return immediately
        if 'rxpk' not in msg['data']:
            return

        # Filter the received packets for new packets that are not in the cache
        new_rxpks = []
        self.vminer_logger.debug(f"PUSH_DATA from GW:{msg['MAC'][-8:]}")
        for rxpk in msg['data']['rxpk']:
            # Generate a key for the received packet
            key = self.__rxpk_key__(rxpk)

            # Check if the packet is a duplicate
            is_duplicate = key in self.rxpk_cache

            # Log the received packet
            description = f"from GW:{msg['MAC'][-8:]} [{rxpk.get('size')}B]: {key}; rssi:{rxpk['rssi']:.0f}dBm, snr:{rxpk['lsnr']:.0f}"
            if packet_is_poc_challenge(rxpk):
                log_level = 'info'
                if is_duplicate:
                    classification = 'repeat chlng.'
                else:
                    classification = 'new    chlng.'
            else:
                log_level = 'debug'
                if is_duplicate:
                    classification = 'repeated packet'
                else:
                    classification = 'new packet'

            if log_level == 'info':
                log = self.vminer_logger.info
            else:
                log = self.vminer_logger.debug
            log(f"{classification} {description}")

            # If the packet is a duplicate, continue to the next packet
            if is_duplicate:
                continue

            # Add the packet to the cache and add it to the list of new packets
            self.rxpk_cache[key] = time.time()
            new_rxpks.append(rxpk)

        # Check if there are no new rxpks to send
        if not new_rxpks:
            # Return if there are no new rxpks
            return

        # Update the msg data with new rxpks
        msg['data']['rxpk'] = new_rxpks

        # Loop through all virtual gateways (vgw) by mac addresses
        for vgw in self.vgateways_by_mac.values():
            # Check if the current msg is generated from the transmission of this vgw
            if msg.get('txMAC') == vgw.mac:
                # Log a debug message and ignore this vgw
                self.vgw_logger.debug(f"ignoring rxpk for vGW {vgw.mac[-8:]}. Its generated from PULL_RESP from this vGW")
                continue

            # Get the rxpks data and address for this vgw
            data, addr = vgw.get_rxpks(copy.deepcopy(msg))
            # Check if address is not None
            if addr is None:
                # Continue to the next iteration if address is None
                continue
            # Send the data to the specified address using socket
            self.sock.sendto(data, addr)

    # Handle the PULL_RESP message
    def handle_PULL_RESP(self, msg, addr=None):
        """
        take PULL_RESP sent from a miner and forward to the appropriate gateway
        :param msg:
        :param addr:
        :return:
        """
        # Get the virtual gateway object by its address
        vgw = self.vgateways_by_addr.get(addr)
        # Check if the virtual gateway is not found
        if not vgw:
            # Log an error message and return
            self.vgw_logger.error(f"PULL_RESP from unknown miner at {addr}, dropping transmit command")
            return
        # Get the destination address for this virtual gateway
        dest_addr = self.gw_listening_addrs.get(vgw.mac)
        # Check if the destination address is not found
        if not dest_addr:
            # Log a warning message
            self.vgw_logger.warning(f"PULL_RESP from {addr} has no matching real gateway, will only be received by Virtual Miners")
        # Get the txpk from the message
        txpk = msg['data'].get('txpk')

        # Adjust the tx power
        txpk = self.adjust_tx_power(txpk)

        # Encode the message into raw message
        rawmsg = messages.encode_message(msg)
        # Check if the destination address is found
        if dest_addr:
            # Send the raw message to the destination address
            self.sock.sendto(rawmsg, dest_addr)
            # Log a message indicating that the PULL_RESP has been forwarded
            self.vgw_logger.info(f"forwarding PULL_RESP from {addr} to gateway {vgw.mac[-8:]}, (freq:{round(txpk['freq'], 2)}, sf:{txpk['datr']}, codr:{txpk['codr']}, size:{txpk['size']})")

        # Create a fake PUSH_DATA message
        fake_push = messages.PULL_RESP2PUSH_DATA(msg, src_mac=vgw.mac)
        # Log a message indicating that a fake rxpk has been created
        self.vgw_logger.info(f"created fake rxpk for PULL_RESP from vgw:{vgw.mac[-8:]}")
        # Handle the fake PUSH_DATA message
        self.handle_PUSH_DATA(msg=fake_push, addr=None)

    def handle_PULL_DATA(self, msg, addr=None):
        """
        take PULL_DATA sent from gateways and record the destination (ip, port) where this gateway MAC can be reached
        :param msg: dictionary containing header and contents of PULL_DATA message
        :param addr: tuple of (ip, port) of message origin
        :return:
        """
        # check if the gateway's MAC address is already recorded
        if msg['MAC'] not in self.gw_listening_addrs:
            # if not, log a message indicating a new gateway has been discovered
            self.vminer_logger.info(f"discovered gateway mac:{msg['MAC'][-8:]} at {addr}. {len(self.gw_listening_addrs) + 1} total gateways")
        # record the destination (ip, port) for the given MAC address
        self.gw_listening_addrs[msg['MAC']] = addr

    # Handle TX_ACK message
    def handle_TX_ACK(self, msg, addr):
        # Extract the token from the message
        token = msg['token']
        # Log the decoded message
        self.vgw_logger.debug(f"Decoded Message: {msg}")
        # Update the JSON data with the correct token
        json_data = None
        if len(msg) > 12:
            json_data = msg[12:]
            json_obj = json.loads(json_data)
            json_obj['token'] = token
            json_data = json.dumps(json_obj).encode('utf-8')
        # Encode the message with the updated JSON data and send it back to all the virtual gateways
        for vgw in self.vgw.values():
            vgw_address = (vgw.server_ip, vgw.port)
            rawmsg = messages.encode_message({'ver': 2, 'token': token, '_NAME_': 'TX_ACK', '_UNIX_TS_': time.time(), 'MAC': vgw.mac, 'data': json_data})
            self.vgw_logger.debug(f"Encoded Message: {rawmsg}")
            self.sock.sendto(rawmsg, vgw_address)
            # Check the error field in the JSON object to determine if the downlink request was accepted or rejected
            if json_data:
                json_obj = json.loads(json_data)
                error = json_obj.get('txpk_ack', {}).get('error', 'NONE')
                if error == 'NONE':
                    # Log a debug message indicating that the downlink request was accepted
                    self.vgw_logger.debug(f"Downlink request accepted by gateway at {vgw_address}")
                else:
                    # Log a debug message indicating that the downlink request was rejected
                    self.vgw_logger.debug(f"Downlink request rejected by gateway at {vgw_address}: {error}")
            else:
                # Log a debug message indicating that the downlink request was accepted
                self.vgw_logger.debug(f"Downlink request accepted by gateway at {vgw_address}")

    # Handle PULL_ACK message
    def handle_PULL_ACK(self, msg, addr):
        rawmsg = messages.encode_message(msg)
        self.sock.sendto(rawmsg, addr)
        self.vgw_logger.debug(f"Decoded Message: {msg}")
        self.vgw_logger.debug(f"Encoded Message: {rawmsg}")
        # Extract the mac address from the message
        mac_address = msg.get('MAC', addr)
        # Log a debug message indicating that a PULL_ACK has been received
        self.vgw_logger.debug(f"PULL_ACK received from gateway at {mac_address}")

    # Handle PUSH_ACK message
    def handle_PUSH_ACK(self, msg, addr):
        rawmsg = messages.encode_message(msg)
        self.sock.sendto(rawmsg, addr)
        self.vgw_logger.debug(f"Decoded Message: {msg}")
        self.vgw_logger.debug(f"Encoded Message: {rawmsg}")
        # Get the mac address from the message or the address
        mac_address = msg.get('MAC', addr)
        # Log a debug message indicating that a PUSH_ACK has been received
        self.vgw_logger.debug(f"PUSH_ACK received from packet forwarder at {mac_address}")

    # Get the message from the socket
    def get_message(self, timeout=None):
        """
        waits for a datagram to be received from socket.  Once received it parses datagram into PROTOCOL.txt defined
        payload.  If successful the parsed message and sending address is returned.  On socket timeout or parsing error
        None, None is returned.
        :param timeout: socket timeout if None will not timeout
        :return: tuple of (message, addr) or (None, None) on error/timeout
        """
        # Set the socket timeout if timeout is provided
        if timeout:
            self.sock.settimeout(timeout)
        try:
            # Receive data from the socket
            data, addr = self.sock.recvfrom(1024)
        # Catch socket timeout or BlockingIOError
        except (socket.timeout, BlockingIOError) as e:
            # Return None, None if there was a timeout
            return None, None
        # Catch ConnectionResetError
        except ConnectionResetError as e:
            # Return None, None if there was a ConnectionResetError
            return None, None
        try:
            # Decode the message
            msg, ack = messages.decode_message(data, return_ack=True)
        # Catch ValueError
        except ValueError as e:
            # Return None, None if there was a ValueError
            return None, None
        # Check if an ack is required
        if ack:
            # Send the ack to the address
            self.sock.sendto(ack, addr)
        # Return the message and the address
        return msg, addr

    # Send stats message
    def send_stats(self):
        """
        Sends stat PUSH_DATA messages from all virtual gateways to corresponding miners
        :return:
        """
        # Update the last_stat_ts with the current time
        self.last_stat_ts = time.time()
        # Loop through all virtual gateways
        for gw in self.vgateways_by_mac.values():
            # Get the stat data and the address
            data, addr = gw.get_stat()
            # Send the data to the address
            self.sock.sendto(data, addr)

    # Send keepalive message
    def send_keepalive(self):
        """
        sends PULL_DATA messages from all virtual gateways
        :return:
        """
        # Update the last_keepalive_ts with the current time
        self.last_keepalive_ts = time.time()
        # Loop through all virtual gateways
        for gw in self.vgateways_by_mac.values():
            # Get the PULL_DATA data and the address
            data, addr = gw.get_PULL_DATA()
            # Send the data to the address
            self.sock.sendto(data, addr)

    # Adjust the tx power
    def adjust_tx_power(self, pk: dict):
        # Increase the power by the tx_power_adjustment
        pk['powe'] += self.tx_power_adjustment
        # Return the adjusted power
        return pk

    # Clean up the socket when the object is deleted
    def __del__(self):
        # Close the socket
        self.sock.close()

# Check if the packet is a POC challenge
def packet_is_poc_challenge(rxpk: dict):
    # Check if the size is 52 and the datr is 'SF9BW125'
    return rxpk.get('size') == 52 and rxpk.get('datr') == 'SF9BW125'


# Configure the logger
def configure_logger(debug=False):
    # Set up the logger
    logformat = '%(asctime)s.%(msecs)03d %(name)-6s:[%(levelname)-8s] %(message)s'
    logging.basicConfig(
        format=logformat,
        datefmt='%Y/%m/%d %H:%M:%S',
        level=logging.DEBUG if debug else logging.INFO,
        filename='middleman.log',
        filemode='a'
    )
    # Create a console handler
    console = logging.StreamHandler()
    # Set the console handler level
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    # Create a formatter
    formatter = logging.Formatter(logformat, datefmt='%Y/%m/%d %H:%M:%S')
    # Set the formatter for the console handler
    console.setFormatter(formatter)
    # Add the console handler to the root logger
    logging.getLogger('').addHandler(console)

# Main function to start the program
def main():
    # Create an argument parser
    parser = argparse.ArgumentParser("forward data from multiple concentrators to multiple miners with coercing of metadata")
    # Add arguments
    parser.add_argument('-p', '--port', help='port to listen for gateway on', default=1680, type=int)
    parser.add_argument('-c', '--configs', help='path where to locate gateway configs', default='gw_configs/', type=str)
    parser.add_argument('-d', '--debug', action='store_true', help="print verbose debug messages")
    parser.add_argument('-k', '--keepalive', help='keep alive interval in seconds', default=10, type=int)
    parser.add_argument('-s', '--stat', help='stat interval in seconds', default=30, type=int)
    parser.add_argument('-t', '--tx-adjust', help='adjust transmit power by some constant (in dB).', type=float, metavar='<adjustment-db>', default=0.0)
    parser.add_argument('-r', '--rx-adjust', help='adjust reported receive power by some constant (in dB).', type=float, metavar='<adjustment-db>', default=0.0)

    # Parse the arguments
    args = parser.parse_args()

    # Configure the logger
    configure_logger(args.debug)

    # Log information messages
    logging.info(f"info log messages are enabled")
    # Log debug messages
    logging.debug(f"debug log messages are enabled")
    logging.debug(f"startup arguments: {args}")

    # Get the configuration paths
    config_paths = []
    for f in os.listdir(args.configs):
        if os.path.isfile(os.path.join(args.configs, f)) and f[-4:].lower() == 'json':
            config_paths.append(os.path.join(args.configs, f))

    # Create a GW2Miner instance
    gw2miner = GW2Miner(args.port, config_paths, args.keepalive, args.stat,
        args.debug, args.tx_adjust, args.rx_adjust)
    logging.info(f"starting Gateway2Miner")
    try:
        # Start the Gateway2Miner instance
        gw2miner.run()
    except FileNotFoundError as e:
        # Log a fatal error message
        logging.fatal("Gateway2Miner returned, packets will no longer be forwarded")
        raise e

# Run the main function if the script is being run as the main module
if __name__ == '__main__':
    main()

