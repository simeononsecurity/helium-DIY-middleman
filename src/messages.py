
"""
Parses messages as defined in https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT

"""

import json
import datetime as dt
import random
import struct
import time

# The code implements a series of classes that define different types of messages used in the protocol
# Each class extends the base Message class and overrides the decode, encode and ack methods as necessary
# The msg_types and msg_types_name dictionaries are used to look up the correct class for a given message type
class Message:
    IDENT = 0xFF
    NAME = "None"

    # Constructor that takes in a binary data argument, and sets it as the data attribute of the class
    def __init__(self, data=b''):
        self.data = data

    # Decode method that takes in a binary data argument, and decodes it into a dictionary
    def decode(self, data=None):
        # If data argument is provided, set the data attribute to the argument
        if data:
            self.data = data

        # Check if the data attribute is valid
        if not self.data or len(self.data) < 4 or self.data[3] != self.IDENT:
            raise ValueError(f"invalid message {data}")

        # Check if the length of data attribute is at least 4 bytes
        if len(self.data) < 4:
            raise ValueError(f"invalid {self.NAME} message")

        # Unpack the binary data into a dictionary
        result = dict(
            ver=self.data[0],
            token=struct.unpack_from('H', self.data[1:])[0],
            identifier=self.data[3],
            _NAME_=self.NAME,
            _UNIX_TS_=time.time()
        )
        return result

    # Encode method that takes in a message object (dictionary) and returns the encoded binary data
    def encode(self, message_object):
        # Pack the message object into binary data
        self.data = struct.pack("=BHB", message_object.get('ver', 2), message_object.get('token'), message_object.get('identifier'))
        return self.data

    # ACK method that returns None
    def ack(self):
        return None

class MsgPushData(Message):
    IDENT = 0x00
    NAME = "PUSH_DATA"

    # Decode method that takes in a binary data argument, and decodes it into a dictionary
    def decode(self, data=None):
        # Call the parent class' decode method
        result = super().decode(data)

        # Check if the length of data attribute is at least 14 bytes
        if len(self.data) < 14:
            raise ValueError(f"invalid {self.NAME} message, too short {len(self.data)}/14 bytes")

        # Add the MAC address to the result dictionary
        result['MAC'] = ':'.join([f"{x:02X}" for x in self.data[4:12]])

        # Load the binary data as JSON and add it to the result dictionary
        result['data'] = json.loads(self.data[12:].decode())
        return result

    # Encode method that takes in a message object (dictionary) and returns the encoded binary data
    def encode(self, message_object):
        # Call the parent class' encode method
        super().encode(message_object)

        # Add the MAC address to the binary data
        self.data += struct.pack('=BBBBBBBB', *[int(x, 16) for x in message_object['MAC'].split(':')])

        # Add the JSON payload to the binary data
        self.data += json.dumps(message_object['data']).encode()
        return self.data

    # ACK method that returns the first 3 bytes of the data attribute, followed by the ACK identifier (0x01)
    def ack(self):
        ack = self.data[:3] + bytes([0x01])
        return ack

class MsgPushAck(Message):
    IDENT = 0x01
    NAME = "PUSH_ACK"


class MsgPullData(Message):
    IDENT = 0x02
    NAME = "PULL_DATA"

    # Decode method that takes in a binary data argument, and decodes it into a dictionary
    def decode(self, data=None):
        # Call the parent class' decode method
        result = super().decode(data)

        # Check if the length of data attribute is at least 12 bytes
        if len(self.data) < 12:
            raise ValueError(f"invalid {self.NAME} message, too short {len(self.data)}/12 bytes")

        # Add the MAC address to the result dictionary
        result['MAC'] = ':'.join([f"{x:02X}" for x in self.data[4:12]])

        return result

    # Encode method that takes in a message object (dictionary) and returns the encoded binary data
    def encode(self, message_object):
        # Call the parent class' encode method
        super().encode(message_object)

        # Add the MAC address to the binary data
        self.data += struct.pack('=BBBBBBBB', *[int(x, 16) for x in message_object['MAC'].split(':')])
        return self.data

    # ACK method that returns the first 3 bytes of the data attribute, followed by the ACK identifier (0x04)
    def ack(self):
        ack = self.data[:3] + bytes([0x04])
        return ack

class MsgPullAck(Message):
    IDENT = 0x04
    NAME = "PULL_ACK"

class MsgPullResp(Message):
    IDENT = 0x03
    NAME = "PULL_RESP"

    # Decode method that takes in a binary data argument, and decodes it into a dictionary
    def decode(self, data=None):
        # Call the parent class' decode method
        result = super().decode(data)

        # Check if the length of data attribute is at least 14 bytes
        if len(self.data) < 14:
            raise ValueError(f"invalid {self.NAME} message, too short {len(self.data)}/14 bytes")

        # Load the binary data as JSON and add it to the result dictionary
        result['data'] = json.loads(self.data[4:].decode())
        return result

    # Encode method that takes in a message object (dictionary) and returns the encoded binary data
    def encode(self, message_object):
        # Call the parent class' encode method
        super().encode(message_object)

        # Add the JSON payload to the binary data
        self.data += json.dumps(message_object['data']).encode()
        return self.data


class MsgTxAck(Message):
    IDENT = 0x05
    NAME = "TX_ACK"

    # Decode method that takes in a binary data argument, and decodes it into a dictionary
    def decode(self, data=None):
        # Call the parent class' decode method
        result = super().decode(data)

        # Check if the length of data attribute is at least 12 bytes
        if len(self.data) < 12:
            raise ValueError(f"invalid {self.NAME} message, too short {len(self.data)}/12 bytes")

        # Add the MAC address to the result dictionary
        result['MAC'] = ':'.join([f"{x:02X}" for x in self.data[4:12]])

        # If the data attribute is longer than 14 bytes, load the rest of the binary data as JSON and add it to the result dictionary
        if len(self.data) > 14:
            result['data'] = json.loads(self.data[12:].decode())

        return result

    # Encode method that takes in a message object (dictionary) and returns the encoded binary data
    def encode(self, message_object):
        # Call the parent class' encode method
        super().encode(message_object)

        # Add the MAC address to the binary data
        self.data += struct.pack('=BBBBBBBB', *[int(x, 16) for x in message_object['MAC'].split(':')])

        # Add the JSON payload to the binary data
        self.data += json.dumps(message_object['data']).encode()
        return self.data


msg_types = {
    # Map the message identifier to its corresponding class
    MsgPushData.IDENT: MsgPushData,
    MsgPushAck.IDENT: MsgPushAck,
    MsgPullData.IDENT: MsgPullData,
    MsgPullAck.IDENT: MsgPullAck,
    MsgPullResp.IDENT: MsgPullResp,
    MsgTxAck.IDENT: MsgTxAck
}

msg_types_name = {
    # Map the message name to its corresponding class
    MsgPushData.NAME: MsgPushData,
    MsgPushAck.NAME: MsgPushAck,
    MsgPullData.NAME: MsgPullData,
    MsgPullAck.NAME: MsgPullAck,
    MsgPullResp.NAME: MsgPullResp,
    MsgTxAck.NAME: MsgTxAck
}


def decode_message(rawmsg, return_ack=False):
    # Check if the length of rawmsg is less than 4 bytes or if the identifier is not in msg_types
    if len(rawmsg) < 4 or rawmsg[3] not in msg_types:
        raise ValueError(f"invalid message: {rawmsg}, too short {len(rawmsg)}/4 bytes")

    # Retrieve the message object from the msg_types dictionary using the identifier
    msg_obj = msg_types[rawmsg[3]](rawmsg)

    # Call the decode method on the message object to get the decoded message body
    msg_body = msg_obj.decode()

    # Call the ack method to get the ack message, if any
    ack = msg_obj.ack()

    # If return_ack is True, return both the decoded message body and the ack message
    if return_ack:
        return msg_body, ack

    # Otherwise, return only the decoded message body
    return msg_body

def encode_message(message_object):
    # Check if the message name is not in msg_types_name
    if message_object.get('_NAME_') not in msg_types_name:
        raise ValueError("invalid message object")

    # Retrieve the message object from the msg_types_name dictionary using the message name
    msg_obj = msg_types_name[message_object.get('_NAME_')]()

    # Call the encode method on the message object to get the encoded message
    rawmsg = msg_obj.encode(message_object)

    return rawmsg

def print_message(rawmsg):
    # Call decode_message to get the decoded message body
    msg_body = decode_message(rawmsg)

    # Print the decoded message body
    print(msg_body)

def PULL_RESP2PUSH_DATA(pull_resp, src_mac):
    # Create a dictionary to represent the message body of the PUSH_DATA message
    push = dict(
        _NAME_=MsgPushData.NAME, # Message name
        identifier=MsgPushData.IDENT, # Message identifier
        ver=2, # Version
        token=random.randint(0, 2**16 - 1), # Token
        MAC=src_mac, # MAC address
        txMAC=src_mac, # txMAC is used to signal generated from tx originating at this MAC
        payload=None
    )
    # Retrieve the txpk data from the PULL_RESP message
    txpk = pull_resp['data']['txpk']
    # Calculate the channel number
    chan = int(round((txpk['freq'] - 903.9) / .2, 0)) + 8
    # Create the payload dictionary
    payload = dict(
        data=txpk['data'],
        size=txpk['size'],
        codr=txpk['codr'],
        datr=txpk['datr'],
        modu=txpk['modu'],
        rfch=txpk['rfch'],
        freq=txpk['freq'],
        tmst=0x00000000, # tmst will be set appropriately for the receiver
        rssi=-113, # set rssi to some reasonable default
        lsnr=-5.5, # set lsnr to some reasonable default
        stat=1, # CRC is ok
        chan=chan # channel
    )
    # Add the payload to the push data field
    push['data'] = dict(rxpk=[payload])
    return push

def trials():
    # Create a dictionary with the payload data
    payload = dict(
        _NAME_=MsgPullData.NAME,  # Name of the message
        identifier=MsgPullData.IDENT,  # Identifier of the message
        ver=2,  # Version of the message
        token=random.randint(0, 2**16 - 1),  # Random token
        MAC='AA:55:5A:00:00:00:00:00'  # MAC address
    )

    # Print the payload data as a dictionary
    print(f"encoding body: {payload}")

    # Encode the payload data into a raw message
    payload_raw = encode_message(payload)

    # Print the encoded raw message
    print(f" to raw: {payload_raw}")

    # Decode the raw message back into the payload data
    payload = decode_message(payload_raw)

    # Print the decoded payload data
    print(f"back to body: {payload}")

# Call the trials function when the script is run as a standalone program
if __name__ == "__main__":
    trials()



