# Standard libs
from typing import Optional
from typing import List

from multiprocessing import Process
from multiprocessing import Queue

import socket

from enum import Enum
from enum import auto

import os
import time
import sys

# Local libs

from RUSHBPacket import RUSHBPacket

from RUSHBHelpers import __DEBUG_MODE_ENABLED__, DebugLinePrinter
from RUSHBHelpers import GenericErrorHandler

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBMultiprocessing.py'

# * ENUMS ----------------------------------------------------------------------

class ChildProcessType(Enum):
    # Process responsible for receiving data from clients and sending them
    #   to the server
    RECEIVER_PROCESS = auto()

    # Process responsbile for sending packets to clients
    SENDER_PROCESS = auto()

    # Process responsible for handling a clients request(s)
    WORKER_PROCESS = auto()

class QueueMessageType(Enum):
    # The client has sent a packet to the server that we need to handle
    CLIENT_PACKET_TO_SERVER = auto()

    # The server is sending a packet to the client
    SERVER_PACKET_TO_CLIENT = auto()

    # A session has finished and we should join the child process back.
    CHILD_PROCESS_FINISHED = auto()

    # # Child process sending over their pid
    # CHILD_SEND_PID = auto()

    # Either parent or child can send an ACK to acknowledge something.
    # Important to keep track of exactly `what` is being acknowledged
    ACK = auto()

class ClientHandlerExpectingPacket(Enum):
    # Expecting a GET packet
    GET_PACKET = auto()

    # Expecting either a NAK, DAT/ACK, or DAT/NAK packet
    DAT_PACKET = auto()

    # Expecting a 
    CLOSE_CONNECTION_PACKET = auto()

# * PARALLEL MESSAGES ----------------------------------------------------------

class QueueContainer(object):
    def __init__(self, fromProcessQueue: Queue, toProcessQueue: Queue,
            socket: Optional[socket.socket]=None):
        self.__fromProcessQueue = fromProcessQueue
        self.__toProcessQueue = toProcessQueue
        self.__sock = socket

    def get_from_process_queue(self):
        """ Queue to read from. """
        return self.__fromProcessQueue

    def get_to_process_queue(self):
        """ Queue to write to. """
        return self.__toProcessQueue

    def get_socket(self):
        return self.__sock

class ChildProcessDataTracker(object):
    def __init__(self, toChildQueue: Queue, process: Process, 
            clientAddress: tuple, processType: ChildProcessType):
        self.__toChildQueue = toChildQueue
        self.__process = process
        self.__clientAddress = clientAddress
        self.__childProcessType = processType
    
    def get_process_type(self):
        return self.__childProcessType

    def get_process_handle(self):
        return self.__process

    def get_to_child_queue(self):
        return self.__toChildQueue

    def get_pid(self):
        return self.__process.pid

    def get_client_address(self):
        return self.__clientAddress

class QueueMessage(object):
    def __init__(self,
            msgType: QueueMessageType,
            msgFrom: int,
            msgData: Optional[RUSHBPacket]=None,
            clientAddress: Optional[tuple]=None):
        
        # Preconditions
        self.__msg_type_and_data_precondition(msgType, msgData, clientAddress)
        self.__msg_from_precondition(msgFrom)


        self.__msgFrom = msgFrom
        self.__msgData = msgData
        self.__clientAddress = clientAddress
        self.__msgType = msgType

    def get_message_type(self):
        return self.__msgType

    def get_message_from(self):
        return self.__msgFrom

    def get_message_data(self):
        return self.__msgData

    def get_client_address(self):
        return self.__clientAddress

    def set_client_address(self, newClientAddress: tuple):
        self.__clientAddress = newClientAddress

    # ? PRECONDITIONS ----------------------------------------------------------

    @staticmethod
    def __msg_type_and_data_precondition(msgType: QueueMessageType, 
            msgData: Optional[RUSHBPacket],
            clientAddress: Optional[tuple]):
        assert isinstance(msgType, QueueMessageType), \
                "msgType must be a valid QueueMessageType"

        if msgType == QueueMessageType.CLIENT_PACKET_TO_SERVER or \
                msgType == QueueMessageType.SERVER_PACKET_TO_CLIENT:
            assert isinstance(msgData, RUSHBPacket), \
                    "msgData must NOT be None"

            if msgType == QueueMessageType.CLIENT_PACKET_TO_SERVER:
                assert isinstance(clientAddress, tuple), \
                        "Client address must be a valid tuple"
                assert len(clientAddress) == 2, \
                        "Client address tuple must have length 2"
        else:
            assert msgData == None, "msgData must be None" 

    @staticmethod
    def __msg_from_precondition(msgFrom: int):
        assert isinstance(msgFrom, int) and msgFrom >= 0, \
                "msgFrom port number must be a valid integer"



# * CHILD PROCESSES ------------------------------------------------------------

class PacketSender_ChildProcess(object):
    def __init__(self, queueContainer: QueueContainer):
        self.__debugPrinter = DebugLinePrinter()
        
        # Queues 
        self.__toParentQueue = queueContainer.get_to_process_queue()
        self.__fromParentQueue = queueContainer.get_from_process_queue()

        self.__sock = queueContainer.get_socket()

        assert isinstance(self.__sock, socket.socket), "Must be a valid socket"

        # Process id of the current child process
        self.__pid = os.getpid()

        self.__classname__ = 'PacketSenderChildProcess'

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("DEBUG: Hello from sender")

    # ? PUBLIC METHODS ---------------------------------------------------------

    def main_loop(self):
        """ Infinite loop. Can't be bothered writing a termination sequence. """
        while True:
            # Get a packet from the parent (wait until we get one)
            response: QueueMessage = self.__fromParentQueue.get(block=True)
            
            clientAddress = response.get_client_address()
            data = response.get_message_data()
            if clientAddress == None or data == None:
                # We expected an actual client address to be sent
                raise Exception("Error, client address or data is None.")

            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("\nSender Process {}: Packet Away!".format(self.__pid))

            self.__sock.sendto(     # type: ignore
                    data.to_bytes(), 
                    clientAddress)
                    

    def get_from_parent_queue(self):
        return self.__fromParentQueue

    def get_to_parent_queue(self):
        return self.__toParentQueue

    def get_pid(self):
        return self.__pid

class PacketReceiver_ChildProcess(object):
    def __init__(self, queueContainer: QueueContainer):
        self.__debugPrinter = DebugLinePrinter()

        # Queues
        self.__toParentQueue = queueContainer.get_to_process_queue()
        self.__fromParentQueue = queueContainer.get_from_process_queue()

        self.__sock = queueContainer.get_socket()

        if not isinstance(self.__sock, socket.socket): 
            raise Exception("Must be a valid socket")

        # Process id of the current child process
        self.__pid = os.getpid()

        self.__serverPort = self.__sock.getsockname()[1]

        self.__classname__ = 'PacketReceiverChildProcess'

        # Print the server port to stdout
        print(self.__serverPort)
        
        # Flush stdout ;)
        sys.stdout.flush()

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("DEBUG: Hello from receiver")

    # ? PUBLIC METHODS ---------------------------------------------------------

    def main_loop(self):
        """ Loops forever (I can't be bothered to write a termination sequence) 
        """
        while True:
            # Tell the server to wait
            message, clientAddress = self.__sock.recvfrom(  # type: ignore
                    RUSHBPacket.get_max_packet_size())
            
            # Convert message to a packet
            packet = RUSHBPacket(bytesRaw=message)

            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("Client address: {}".format(clientAddress))

            # Send this packet to the main process for further processing
            self.__toParentQueue.put(QueueMessage(
                msgType=QueueMessageType.CLIENT_PACKET_TO_SERVER,
                msgFrom=self.__pid,
                msgData=packet,
                clientAddress=clientAddress))

    def get_from_parent_queue(self):
        return self.__fromParentQueue

    def get_to_parent_queue(self):
        return self.__toParentQueue

    def get_pid(self):
        return self.__pid

class ClientHandler_ChildProcess(object):
    def __init__(self, queueContainer: QueueContainer):
        self.__debugPrinter = DebugLinePrinter()

        self.__classname__ = 'ClientHandlerChildProcess'

        # Queues
        self.__toParentQueue = queueContainer.get_to_process_queue()
        self.__fromParentQueue = queueContainer.get_from_process_queue()

        self.__clientAddress = ()

        # Process id of the current child process
        self.__pid = os.getpid()

        # Sequence number counter (method of keeping track of the packets that 
        #       are sent)
        self.__sequenceNumber = 1
        self.__lastSequenceNumber = 0

        self.__expectingAcknowledgementNumber = 0

        self.__lastAcknowledgementNumber = 0

        # Offset for the first sequence number the server recieved before 
        #   returning [DAT / ACK] packets
        self.__datPacketAcknowledgementOffset = 1

        self.__requiresChecksum: bool = False

        # List of packets to send, we keep a complete copy of all the packets
        # in case of the need for retransmission
        self.__packetsToSend = []

        # Current packet we need to send
        self.__packetCounter = 0

        # By default, client will expect a GET packet
        self.__isExpecting: ClientHandlerExpectingPacket = \
                ClientHandlerExpectingPacket.GET_PACKET

        self.__isAwaitingAck: bool = False

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("DEBUG: Hello from client handler")

    def get_from_parent_queue(self):
        return self.__fromParentQueue

    def get_to_parent_queue(self):
        return self.__toParentQueue

    def get_pid(self):
        return self.__pid

    def main_loop(self):
        """ Main loop for the child process. 
        
        This is where we implement the state machine, child assumes that all 
        packets are valid
        """
        while True:
            # Get instruction from the parent
            if not self.__isAwaitingAck:
                message: QueueMessage = self.__fromParentQueue.get(block=True)
                
                temp = message.get_message_data()
                if temp == None:
                    # Ignore malformed packets
                    continue

                if not self.__check_flags_valid(packet=temp):
                    # Ignore invalid packets
                    continue

                if not self.__check_sequence_number_valid(packet=temp):
                    # Ignore invalid packets
                    continue
            else:
                temp = self.__polling_timeout_queue()

                if temp == None:
                    # Error handling
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(__filename__)
                        print("\nWorker {} timeout".format(self.__pid))
                        print("Expected {}".format(self.__isExpecting))
                        print("Is Awaiting ACK {}".format(self.__isAwaitingAck))

                    # We did not recieve the acknowledgement in time, hence
                    # retransmit the previous packet
                    if self.__isExpecting == ClientHandlerExpectingPacket.\
                            DAT_PACKET:
                        # Retransmit previous packet
                        self.__packetCounter -= 1
                        self.__server_send_dat_packet(
                            datPacket=self.__packetsToSend[ # type: ignore
                                    self.__packetCounter],
                            ackNum=self.__lastAcknowledgementNumber)
                        self.__packetCounter += 1
                        
                    elif self.__isExpecting == ClientHandlerExpectingPacket.\
                            CLOSE_CONNECTION_PACKET:
                        self.__server_send_fin_ack_packet(
                                    self.__lastAcknowledgementNumber)
                    continue
                else:
                    # We got the message in time :D
                    message = temp
                
            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("\nWorker {} received data".format(self.__pid))


            packet = message.get_message_data()

            if packet == None:
                raise Exception("Process [ {} ]: Packet == None".format(
                        self.__pid))

            if self.__requiresChecksum:
                # Check that the client has set the CHK flag on this packet
                if packet.get_chk_flag() == 0:
                    continue    # Invalid packet

            # [ GET ] flag handler
            if packet.get_get_flag() and self.__isExpecting == \
                    ClientHandlerExpectingPacket.GET_PACKET:
                self.__clientAddress = message.get_client_address()

                if self.__clientAddress == None:
                    raise Exception("Process [ {} ]: Recieved client " + \
                            "address of None".format(self.__pid))
                
                # If the chk flag is set, validate the checksum
                if packet.get_chk_flag():
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(
                                __filename__)
                        print("\nWorker {}: Client requires checksum".format(
                                self.__pid))
                    if not packet.validate_checksum(
                            payloadBytes=packet.payload_to_bytes(),
                            checksum=packet.get_check_sum()):
                        if __DEBUG_MODE_ENABLED__:
                            self.__debugPrinter.debug_message_line_print(
                                    __filename__)
                            print("Original checksum INVALID!")
                        continue
                    self.__requiresChecksum = True

                # Handle the get packet
                self.__packet_GET_handler(packet=packet)

            # [ DAT / ACK ] flag handler
            elif packet.get_ack_flag() and packet.get_dat_flag() and \
                    self.__isExpecting == ClientHandlerExpectingPacket.DAT_PACKET:
                self.__packet_DAT_ACK_handler(packet=packet)

            # [ DAT / NAK ] flag handler
            elif packet.get_nak_flag() and packet.get_dat_flag() and \
                    self.__isExpecting == ClientHandlerExpectingPacket.\
                            DAT_PACKET:
                self.__packet_DAT_NAK_handler(packet=packet)

            # [ ACK / FIN ] flag handler
            elif packet.get_ack_flag() and packet.get_fin_flag():
                # Handle the [ FIN / ACK ]
                self.__packet_ACK_FIN_handler(packet=packet)
                
                # Break out of the loop and join with the main process
                break
        
        # Join with the main process (this is done by the main process calling
        #   p.join() on the childs process handle)
    
    # ? PRIVATE METHODS --------------------------------------------------------

    def __packet_GET_handler(self, packet: RUSHBPacket):
        """"""
        self.__packetsToSend = self.__get_file(packet.get_data(),
                packet.get_sequence_number())
        
        # Record the last received packet number
        self.__lastSequenceNumber = packet.get_sequence_number()

        if self.__packetsToSend == None:
            # We couldn't find a file here, close the connection
            # self.__lastAcknowledgementNumber = packet.\
            #         get_sequence_number()
            self.__server_send_fin_packet(
                    self.__lastAcknowledgementNumber)
            self.__isExpecting = ClientHandlerExpectingPacket.\
                    CLOSE_CONNECTION_PACKET
        else:
            self.__datPacketAcknowledgementOffset = \
                    packet.get_sequence_number()
            # Send the first data packet and wait for subsequent 
            #   [DAT/ACK] packets.
            # self.__lastAcknowledgementNumber = packet.\
            #         get_sequence_number()
            self.__server_send_dat_packet(
                    datPacket=self.__packetsToSend[
                            self.__packetCounter],
                    ackNum=self.__lastAcknowledgementNumber)
            self.__isExpecting = ClientHandlerExpectingPacket.DAT_PACKET
            self.__packetCounter += 1

    def __packet_DAT_ACK_handler(self, packet: RUSHBPacket):
        """"""
        # Record the last received packet number
        self.__lastSequenceNumber = packet.get_sequence_number()

        if isinstance(self.__packetsToSend, list) and \
                len(self.__packetsToSend) != self.__packetCounter:
            # Send the next packet in the list
            # self.__lastAcknowledgementNumber = packet.\
            #         get_sequence_number()
            self.__server_send_dat_packet(
                    datPacket=self.__packetsToSend[
                            self.__packetCounter],
                    ackNum=self.__lastAcknowledgementNumber)
            self.__packetCounter += 1
        else:
            # Final packet has been sent, begin sending the FIN sequence
            # self.__lastAcknowledgementNumber = packet.\
            #         get_sequence_number()
            self.__server_send_fin_packet(
                    self.__lastAcknowledgementNumber)
            self.__isExpecting = ClientHandlerExpectingPacket.\
                    CLOSE_CONNECTION_PACKET

    def __packet_DAT_NAK_handler(self, packet: RUSHBPacket):
        # Retransmit the packet specified by the client.
        
        # acknowledgementNum = packet.get_acknowledgement_number()

        # Record the last received packet number
        self.__lastSequenceNumber = packet.get_sequence_number()

        offsetAdjIndex = packet.get_acknowledgement_number() - \
                    self.__datPacketAcknowledgementOffset
        
        if isinstance(self.__packetsToSend, list) and \
                offsetAdjIndex < len(self.__packetsToSend):
            # Retransmit the specified packet
            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("\nWorker {}".format(self.__pid))
                print("[DAT/NAK] Received, retransmitting packet")
                print("Acknowledgement number from client packet: {}"\
                        .format(packet.get_acknowledgement_number()))
                print("Offset: {}".format(
                        self.__datPacketAcknowledgementOffset))

            self.__server_send_dat_packet(
                        datPacket=self.__packetsToSend[ # type: ignore
                                offsetAdjIndex],
                        ackNum=0)
        else:
            # Conditions for retransmission not met, ignore
            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("\nWorker {}".format(self.__pid))
                print("[DAT/NAK] conditions not met")
                print("packetsToSend is list: {}".format(
                        isinstance(self.__packetsToSend, list)))
                
                if isinstance(self.__packetsToSend, list):
                    print("offset ackowledgementNum < num packets: {}"\
                            .format(offsetAdjIndex < \
                                    len(self.__packetsToSend)))

    def __packet_ACK_FIN_handler(self, packet: RUSHBPacket):
        # Handle the [ FIN / ACK ]
        
        # Record the last received packet number
        self.__lastSequenceNumber = packet.get_sequence_number()

        self.__lastAcknowledgementNumber = packet.\
                    get_sequence_number()
        self.__server_send_fin_ack_packet(
                self.__lastAcknowledgementNumber)

    def __polling_timeout_queue(self):
        """ Simple polling queue that waits for timeout before returning. 
        
        inb4 "just using `.get(timeout=4)` bro"

        If that fails, the `.get()` method will raise an `Empty` exception.
        
        For some weird reason, the method won't actually work when placed inside 
            of a `try except` block. Now I don't really care enough to find out
            why, perhaps its a bug from an the interpreter I'm using, 3.9.1
        """
        maxSleepDuration = 4
        sleepIncrements = 0.1
        totalSleepDuration = 0
        while True:
            if self.__fromParentQueue.empty():
                time.sleep(sleepIncrements)
                totalSleepDuration += sleepIncrements
            else:
                message: QueueMessage = self.__fromParentQueue.get()
                
                temp = message.get_message_data()

                if temp == None:
                    # Ignore malformed packets
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(__filename__)
                        print("\nWorker {}: Malformed packet".format(
                                    self.__pid))
                    continue

                if not self.__check_flags_valid(packet=temp):
                    # Ignore invalid packets
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(__filename__)
                        print("\nWorker {}: Flags invalid".format(
                                    self.__pid))
                    continue
                
                if self.__expectingAcknowledgementNumber != temp\
                        .get_acknowledgement_number():
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(__filename__)
                        print("\nWorker {}: Acknowledgement number invalid"\
                                .format(self.__pid))
                        print("Expected Ack#: {}".format(
                                self.__expectingAcknowledgementNumber))
                        print("Received: {}".format(
                                temp.get_acknowledgement_number()))
                    continue

                if not self.__check_sequence_number_valid(packet=temp):
                    # Ignore invalid packets
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(__filename__)
                        print("\nWorker {}: Sequence number invalid".format(
                                    self.__pid))
                    continue

                

                if self.__requiresChecksum:
                    # Validate checksum
                    packet = message.get_message_data()

                    if not isinstance(packet, RUSHBPacket):
                        # Invalid packet, ignore
                        continue

                    if not packet.validate_checksum(
                            payloadBytes=packet.payload_to_bytes(),
                            checksum=packet.get_check_sum()):
                        # Invalid checksum, ignore
                        if __DEBUG_MODE_ENABLED__:
                            self.__debugPrinter.debug_message_line_print(__filename__)
                            print("\nWorker {}: Checksum invalid".format(self.__pid))
                        continue

                return message

            if totalSleepDuration >= maxSleepDuration:
                return None

    def __get_file(self, filename: str, acknowledgementNumber: int):
        """ Attempts to get a specified file. 
        
        ARGS:
        - filename: relative path to the file.
        - acknowledgementNumber: The sequence number of the GET packet we're 
                acknowledging

        RETURNS:
        - If the file exists, this method will read in the data from the file,
            split its contents into packets, and returns a list of `RUSHBPacket`
            objects. Otherwise returns `None`.
        """
        count = 0
        try:
            # Open the file
            filename = filename.replace(chr(0), "")
            
            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("Attempting to open filename: {}".format(filename))
            
            f = open(filename, "r")

            # Read the file
            data = f.read()
            
            returnPacketsList: List[RUSHBPacket] = []

            # Create packets from it
            while len(data[count * RUSHBPacket.get_max_payload_size():]) > \
                    RUSHBPacket.get_max_payload_size():
                returnPacketsList.append(RUSHBPacket(inputDict={
                    'sequence_number': self.__sequenceNumber,
                    'acknowledgement_number': acknowledgementNumber,
                    'checksum': 0,
                    'ack_flag': 0,
                    'nak_flag': 0,
                    'get_flag': 0,
                    'dat_flag': 1,
                    'fin_flag': 0,
                    'chk_flag': 0,
                    'enc_flag': 0,
                    'packet_version': 2,
                    'data': data[count*RUSHBPacket.get_max_payload_size():\
                            (count+1)*RUSHBPacket.get_max_payload_size()]
                }))
                count += 1
                self.__sequenceNumber += 1
            # Get the last packet
            returnPacketsList.append(RUSHBPacket(inputDict={
                'sequence_number': self.__sequenceNumber,
                'acknowledgement_number': acknowledgementNumber,
                'checksum': 0,
                'ack_flag': 0,
                'nak_flag': 0,
                'get_flag': 0,
                'dat_flag': 1,
                'fin_flag': 0,
                'chk_flag': 0,
                'enc_flag': 0,
                'packet_version': 2,
                'data': data[count*RUSHBPacket.get_max_payload_size():]
            }))
            count += 1
            self.__sequenceNumber += 1

            return returnPacketsList
        
        except FileNotFoundError as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            geh = GenericErrorHandler()
            geh.debug_print_error(filename=__filename__,
                    className=self.__classname__,
                    methodName="__get_file",
                    lineNum=exc_tb.tb_lineno,   # type: ignore
                    exception=e)
            return None

    def __server_send_dat_packet(self, datPacket: RUSHBPacket, ackNum: int):
        """ Tell main to send a [DAT] message to the client. """
        
        datPacket.set_acknowledgement_number(ackNum)

        # Compute the checksum
        if self.__requiresChecksum:
            datPacket.set_check_sum(datPacket.create_checksum_from_data(
                onesComplement=True))
            datPacket.set_chk_flag(True)

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("Sending [DAT] packet to client")
            datPacket.debug_print_contents()
        
        self.__expectingAcknowledgementNumber = datPacket\
                .get_sequence_number()

        self.__toParentQueue.put(QueueMessage(
                msgType=QueueMessageType.SERVER_PACKET_TO_CLIENT,
                msgFrom=self.__pid,
                msgData=datPacket))
        self.__isAwaitingAck = True

    def __server_send_fin_packet(self, acknowledgementNumber: int):
        """ Tell main to send a [FIN] message to end the connection. """
        # Create the packet
        finPacket = RUSHBPacket(inputDict={
            'sequence_number': self.__sequenceNumber,
            'acknowledgement_number': acknowledgementNumber,
            'checksum': 0,
            'ack_flag': 0,
            'nak_flag': 0,
            'get_flag': 0,
            'dat_flag': 0,
            'fin_flag': 1,
            'chk_flag': 0,
            'enc_flag': 0,
            'packet_version': 2,
            'data': ''
        })

        if self.__requiresChecksum:
            finPacket.set_check_sum(finPacket.create_checksum_from_data(
                    onesComplement=True))

            finPacket.set_chk_flag(True)

        self.__expectingAcknowledgementNumber = finPacket\
                .get_sequence_number()

        self.__sequenceNumber += 1

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("Sending [FIN] message to client")
            finPacket.debug_print_contents()

        # Send off the fin packet
        self.__toParentQueue.put(QueueMessage(
                msgType=QueueMessageType.SERVER_PACKET_TO_CLIENT,
                msgFrom=self.__pid,
                msgData=finPacket))
        
        # self.__isAwaitingAck = True

    def __check_sequence_number_valid(self, packet: RUSHBPacket):
        """ Checks if the sequence number recieved is valid. """
        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("\nWorker {}: Recved sequence number: {}".format(self.__pid, 
                    packet.get_sequence_number()))
            print("Last recved sequence number: {}".format(
                    self.__lastSequenceNumber))
        if packet.get_sequence_number() != (self.__lastSequenceNumber + 1):
            return False
        return True

    def __check_flags_valid(self, packet: RUSHBPacket):
        """ Checks if the various flags specified are valid. """
        if self.__isExpecting == ClientHandlerExpectingPacket.GET_PACKET:
            # Check [ GET ] packet flags
            if packet.get_get_flag() and \
                    not packet.get_nak_flag() and \
                    not packet.get_ack_flag() and \
                    not packet.get_dat_flag() and \
                    not packet.get_fin_flag() and \
                    not packet.get_enc_flag():
                return True
            # Unknown combination
            else:
                if __DEBUG_MODE_ENABLED__:
                    self.__debugPrinter.debug_message_line_print(__filename__)
                    print("Worker {}: GET packet flags invalid".format(
                            self.__pid))
                return False
        elif self.__isExpecting == ClientHandlerExpectingPacket.DAT_PACKET:
            # Check [ DAT/ACK ] packet flags
            if packet.get_ack_flag() and \
                    not packet.get_nak_flag() and \
                    not packet.get_get_flag() and \
                    packet.get_dat_flag() and \
                    not packet.get_fin_flag() and \
                    not packet.get_enc_flag():
                if self.__requiresChecksum and packet.get_chk_flag():
                    return True
                elif not self.__requiresChecksum and not packet.get_chk_flag():
                    return True
                else:
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(__filename__)
                        print("Worker {}: DAT/ACK packet flags invalid".format(
                                self.__pid))
                    return False
            # Check [ DAT / NAK ] packet flags
            elif not packet.get_ack_flag() and \
                    packet.get_nak_flag() and \
                    not packet.get_get_flag() and \
                    packet.get_dat_flag() and \
                    not packet.get_fin_flag() and \
                    not packet.get_enc_flag():
                if self.__requiresChecksum and packet.get_chk_flag():
                    return True
                elif not self.__requiresChecksum and not packet.get_chk_flag():
                    return True
                else:
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(
                                __filename__)
                        print("Worker {}: DAT/NAK packet flags invalid".format(
                                self.__pid))
                    return False
            # Unknown combination
            else:
                if __DEBUG_MODE_ENABLED__:
                    self.__debugPrinter.debug_message_line_print(__filename__)
                    print("Worker {}: DAT packet flags invalid".format(
                            self.__pid))
                return False
        # Client is 
        elif self.__isExpecting == ClientHandlerExpectingPacket.\
                CLOSE_CONNECTION_PACKET:
            # Check [ FIN / ACK ] packet flags
            if packet.get_ack_flag() and \
                    not packet.get_nak_flag() and \
                    not packet.get_get_flag() and \
                    not packet.get_dat_flag() and \
                    packet.get_fin_flag() and \
                    not packet.get_enc_flag():
                if self.__requiresChecksum and packet.get_chk_flag():
                    return True
                elif not self.__requiresChecksum and not packet.get_chk_flag():
                    return True
                else:
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(
                                __filename__)
                        print("Worker {}: FIN/ACK packet flags invalid".format(
                                self.__pid))
                    return False
            # Check [ FIN/NAK ] packet flags
            elif not packet.get_ack_flag() and \
                    packet.get_nak_flag() and \
                    not packet.get_get_flag() and \
                    not packet.get_dat_flag() and \
                    packet.get_fin_flag() and \
                    not packet.get_enc_flag():
                if self.__requiresChecksum and packet.get_chk_flag():
                    return True
                elif not self.__requiresChecksum and not packet.get_chk_flag():
                    return True
                else:
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(
                                __filename__)
                        print("Worker {}: FIN/NAK packet flags invalid".format(
                                self.__pid))
                    return False
            # Unknown combination
            else:
                if __DEBUG_MODE_ENABLED__:
                    self.__debugPrinter.debug_message_line_print(__filename__)
                    print("Worker {}: FIN packet flags invalid".format(
                            self.__pid))
                return False
        else:
            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("Worker {}: Unknown flag combination".format(
                        self.__pid))
            return False

    def __server_send_fin_ack_packet(self, acknowledgementNumber: int):
        """ Server sends [FIN/ACK] message to end the connection. """
        # Create the packet
        finAckPacket = RUSHBPacket(inputDict={
            'sequence_number': self.__sequenceNumber,
            'acknowledgement_number': acknowledgementNumber,
            'checksum': 0,
            'ack_flag': 1,
            'nak_flag': 0,
            'get_flag': 0,
            'dat_flag': 0,
            'fin_flag': 1,
            'chk_flag': 0,
            'enc_flag': 0,
            'packet_version': 2,
            'data': ''
        })

        if self.__requiresChecksum:
            finAckPacket.set_check_sum(finAckPacket.create_checksum_from_data(
                    onesComplement=True))
            
            finAckPacket.set_chk_flag(True)

        self.__sequenceNumber += 1

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("Sending [FIN/ACK] message to client")
            finAckPacket.debug_print_contents()

        # Send off the fin packet
        self.__toParentQueue.put(QueueMessage(
                msgType=QueueMessageType.SERVER_PACKET_TO_CLIENT,
                msgFrom=self.__pid,
                msgData=finAckPacket))
        
        # Sleep for a little bit (I'm too lazy to implement synchronised queues)
        time.sleep(0.1)

        # Send off process is done message
        self.__toParentQueue.put(QueueMessage(
                msgType=QueueMessageType.CHILD_PROCESS_FINISHED,
                msgFrom=self.__pid))