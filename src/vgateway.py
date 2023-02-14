import datetime as dt
import time
import random
import logging

if __name__ == "__main__":
    from modify_rxpk import RXMetadataModification
    from messages import decode_message, encode_message, MsgPullData, MsgPushData, MsgPullResp, MsgPullAck, MsgPushAck, MsgTxAck
else:
    from .modify_rxpk import RXMetadataModification
    from .messages import decode_message, encode_message, MsgPullData, MsgPushData, MsgPullResp, MsgPullAck, MsgPushAck, MsgTxAck


class VirtualGateway:
    def __init__(self, mac, server_address, port_up, port_dn, rx_power_adjustment):
        """
        Initialize the Virtual Gateway instance
        
        :param mac: MAC address of the virtual gateway
        :param server_address: Server address to connect to
        :param port_up: Port for uplink messages
        :param port_dn: Port for downlink messages
        :param rx_power_adjustment: Adjustment value for the RX power level
        """
        # Set the MAC address, server address, and ports for uplink and downlink messages
        self.mac = mac
        self.port_up = port_up
        self.port_dn = port_dn
        self.server_address = server_address

        # Initialize counters for the number of received and transmitted packets
        self.rxnb = 0
        self.txnb = 0

        # Initialize the RX metadata modifier
        self.rxmodifier = RXMetadataModification(rx_power_adjustment)

        # Initialize the logger for the virtual gateway
        self.logger = logging.getLogger(f"VGW:{self.mac[-2:]}")

    def get_stat(self):
        """
        Get the statistics for the virtual gateway
        
        :return: Tuple of raw bytearray data and destination (port, IP) to send the data, or None, None if no message should be sent
        """
        # Create a payload with the statistics information
        payload = dict(
            stat=dict(
                time=dt.datetime.utcnow().isoformat()[:19] + " GMT",  # Current time in ISO format
                rxnb=self.rxnb,  # Number of received packets
                rxok=self.rxnb,  # Number of received packets
                rxfw=self.rxnb,  # Number of received packets
                txnb=self.txnb,  # Number of transmitted packets
                dwnb=self.txnb,  # Number of transmitted packets
                ackr=100.0  # Acknowledgment rate (100% as no error is considered)
            )
        )
        
        # Return the encoded message using the `__get_PUSH_DATA__` method
        return self.__get_PUSH_DATA__(payload)

    def get_rxpks(self, msg):
        """
        Modify and return received packets

        :param msg: Received message
        :return: Tuple of raw bytearray data and destination (port, IP) to send the data, or None, None if no new packets should be sent
        """
        # Initialize an empty array to store the modified RX packets
        new_rxpks = []

        # Iterate through each received packet in the message
        for rx in msg['data']['rxpk']:

            # Modify the metadata of the received packet
            modified_rx = self.rxmodifier.modify_rxpk(rx, src_mac=msg['MAC'], dest_mac=self.mac)

            # Add the modified RX packet to the array of packets to be sent
            new_rxpks.append(modified_rx)

        # If there are no new packets to send, return None, None
        if not new_rxpks:
            return None, None

        # Create a payload with the modified RX packets
        payload = dict(rxpk=new_rxpks)

        # Update the count of received packets
        self.rxnb += len(new_rxpks)

        # Log the message to be sent
        self.logger.debug(f"sending PUSH_DATA with {len(new_rxpks)} packets from vGW:{self.mac[-8:]} to miner {(self.server_address, self.port_up)}")

        # Return the encoded message using the `__get_PUSH_DATA__` method
        return self.__get_PUSH_DATA__(payload)

    def __get_PUSH_DATA__(self, payload):
        """
        Encodes and returns a PUSH_DATA message with the specified payload

        :param payload: Dictionary containing the payload for the message
        :return: Tuple of raw bytearray data and destination (port, IP) to send the data
        """
        # Create a dictionary with the necessary fields for the PUSH_DATA message
        top = dict(
            _NAME_=MsgPushData.NAME,
            identifier=MsgPushData.IDENT,
            ver=2,
            token=random.randint(0, 2**16-1),
            MAC=self.mac,
            data=payload
        )

        # Encode the message and return the raw bytearray data and destination (port, IP)
        payload_raw = encode_message(top)
        return payload_raw, (self.server_address, self.port_up)

    def get_PULL_DATA(self):
        """
        Encodes and returns a PULL_DATA message

        :return: Tuple of raw bytearray data and destination (port, IP) to send the data
        """
        # Create a dictionary with the necessary fields for the PULL_DATA message
        payload = dict(
            _NAME_=MsgPullData.NAME,
            identifier=MsgPullData.IDENT,
            ver=2,
            token=random.randint(0, 2**16-1),
            MAC=self.mac
        )

        # Encode the message and return the raw bytearray data and destination (port, IP)
        payload_raw = encode_message(payload)
        return payload_raw, (self.server_address, self.port_dn)

    
    # todo: refactor messages.py to support the proper encoding of the below definitions
    # https://github.com/helium/packet_forwarder/blob/master/PROTOCOL.TXT
    #  ### 5.5. TX_ACK packet ###

    # That packet type is used by the gateway to send a feedback to the server
    # to inform if a downlink request has been accepted or rejected by the gateway.
    # The datagram may optionnaly contain a JSON string to give more details on
    # acknoledge. If no JSON is present (empty string), this means than no error
    # occured.

    #  Bytes  | Function
    # :------:|---------------------------------------------------------------------
    #  0      | protocol version = 2
    #  1-2    | same token as the PULL_RESP packet to acknowledge
    #  3      | TX_ACK identifier 0x05
    #  4-11   | Gateway unique identifier (MAC address)
    #  12-end | [optional] JSON object, starting with {, ending with }, see section 6

    # def get_TX_ACK(self, payload=""):
    #     """
    #     Sends TX_ACK message to miner with payload contents
    #     :param token: token from PULL_RESP packet to acknowledge
    #     :param payload: [optional] JSON object, starting with {, ending with }, see section 6
    #     :return:
    #     """
    #     top = dict(
    #         _NAME_=MsgTxAck.NAME,
    #         identifier=MsgTxAck.IDENT,
    #         ver=2,
    #         token=random.randint(0, 2**16-1),
    #         MAC=self.mac,
    #         data=payload
    #     )
    #     payload_raw = encode_message(top)
    #     return payload_raw, (self.server_address, self.port_up)

    ### 3.3. PUSH_ACK packet ###

    # That packet type is used by the server to acknowledge immediately all the 
    # PUSH_DATA packets received.

    #  Bytes  | Function
    # :------:|---------------------------------------------------------------------
    #  0      | protocol version = 2
    #  1-2    | same token as the PUSH_DATA packet to acknowledge
    #  3      | PUSH_ACK identifier 0x01

    # def get_PUSH_ACK(self, payload):
    #     """
    #     Sends PUSH_ACK message to miner with payload contents
    #     :param payload: raw payload
    #     :return:
    #     """
    #     top = dict(
    #         _NAME_=MsgPushAck.NAME,
    #         identifier=MsgPushAck.IDENT,
    #         ver=2,
    #         token=random.randint(0, 2**16-1),
    #         MAC=self.mac,
    #         data=payload
    #     )
    #     payload_raw = encode_message(top)
    #     return payload_raw, (self.server_address, self.port_up)


    ### 5.3. PULL_ACK packet ###

    # That packet type is used by the server to confirm that the network route is 
    # open and that the server can send PULL_RESP packets at any time.

    #  Bytes  | Function
    # :------:|---------------------------------------------------------------------
    #  0      | protocol version = 2
    #  1-2    | same token as the PULL_DATA packet to acknowledge
    #  3      | PULL_ACK identifier 0x04

    # def get_PULL_ACK(self, payload):
    #     """
    #     Sends PULL_ACK message to miner with payload contents
    #     :param payload: raw payload
    #     :return:
    #     """
    #     top = dict(
    #         _NAME_=MsgPullAck.NAME,
    #         identifier=MsgPullAck.IDENT,
    #         ver=2,
    #         token=random.randint(0, 2**16-1),
    #         MAC=self.mac,
    #         data=payload
    #     )
    #     payload_raw = encode_message(top)
    #     return payload_raw, (self.server_address, self.port_up)