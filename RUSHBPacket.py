# Standard libs
from typing import Optional
from typing import List

from enum import Enum
from enum import auto
import sys

# Local Libs
from RUSHBHelpers import __DEBUG_MODE_ENABLED__
from RUSHBHelpers import GenericErrorHandler
from RUSHBHelpers import DebugLinePrinter

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBPacket.py'

# * ENUMS ----------------------------------------------------------------------

class RUSHBPacketInitState(Enum):
    PACKET_INIT_OK = auto()
    PACKET_INIT_FAILED = auto()

# * HELPERS --------------------------------------------------------------------

class RUSHBPacketSequenceNumberTracker(object):
    """ Keeps track of the sequence number, can be used to detect sequence number
        Errors. 
    """
    def __init__(self):
        # Server starts with sequence number 1
        self.__startingSequenceNumber = 1
        self.__lastAcknowledgementNumber = 1
        pass

    def increment_sequence_number(self):
        """ Increments the sequence number. """
        self.__startingSequenceNumber += 1

    def increment_last_acknowledgement_number(self):
        self.__lastAcknowledgementNumber += 1

    def last_acknowledgement_number(self):
        pass
    
    def get_expected_sequence_number_ACK(self):
        """ Returns the sequence number expected upon receiving an ACK. 
        
        When recieving an ACK packet, we need to check that the sequence number
            is correct.
        """
        return self.__startingSequenceNumber + 1

# * MAIN -----------------------------------------------------------------------

class RUSHBPacket(object):
    """
    RUSHB packet has the following structure:

    ----------------------------------------------------------------------------
    | B  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
    | 0  |                          Sequence Number                            |
    | 16 |                      Acknowledgement Number                         |
    | 32 |                  Checksum (all 0s if not used)                      |
    | 46 | Flags (7 bits total)      | Reserved (all 0s, 6 bit) |  0 |  1 |  0 |
    |    |                                                                     |
    | .. |                           ASCII Payload                             |
    |    |                                                                     |
    ----------------------------------------------------------------------------
    
    ARGS:
    - bytesRaw 

    SUPPORTED VERSION(s):
    - v2 (010)
    """
    
    def __init__(self, bytesRaw: Optional[bytes]=None, 
            inputDict: Optional[dict]=None):
        
        self.__classname__ = 'RUSHBPacket'
        self.__debugPrinter = DebugLinePrinter()

        # Preconditions
        if bytesRaw == None:
            self.__init_from_dict_precondition(inputDict=inputDict)
            self.__init_from_dict(inputDict=inputDict)  # type: ignore
        else:
            self.__init__from_bytes_precondition(bytesRaw=bytesRaw)
            self.__init_from_bytes(bytesRaw=bytesRaw)
    
    # ? PUBLIC METHODS ---------------------------------------------------------

    def get_packet_init_status(self):
        """ Returns the packet init status. 
        
        NOTE:
        - This variable will always be set (regardless of whether initialisation
            of the class succeeds or fails).
        """
        return self.__packetInitStatus

    def get_sequence_number(self):
        return self.__sequenceNumber

    def get_acknowledgement_number(self):
        return self.__acknowledgementNumber

    def set_acknowledgement_number(self, newAckNum: int):
        # Precondiitons
        self.__set_acknowledgement_number_precondition(newAckNum=newAckNum)
        self.__acknowledgementNumber = newAckNum

    def get_check_sum(self):
        return self.__checksum

    def set_check_sum(self, newChecksum: int):
        # Precondition
        self.__checksum = newChecksum

    def get_ack_flag(self):
        return self.__ACKFlag

    def get_nak_flag(self):
        return self.__NAKFlag

    def get_get_flag(self):
        return self.__GETFlag

    def get_dat_flag(self):
        return self.__DATFlag

    def get_fin_flag(self):
        return self.__FINFlag

    def get_chk_flag(self):
        return self.__CHKFlag
    
    def set_chk_flag(self, chkOn: bool):
        if chkOn:
            self.__CHKFlag = 1
        else:
            self.__CHKFlag = 0
    
    def get_enc_flag(self):
        return self.__ENCFlag

    def get_packet_version(self):
        return self.__packetVersion

    def get_data(self):
        return self.__data

    def debug_print_contents(self):
        """ Prints out the contents of the packet to stdout. """

        print("Packet Seq Num: {}".format(self.get_sequence_number()))
        print("Packet Acknowledgement Num: {}".format(
                self.get_acknowledgement_number()))
        print("Packet Checksum: {}\n".format(self.get_check_sum()))
        print("Flags:")
        print("\tACK: {}".format(self.get_ack_flag()))
        print("\tNAK: {}".format(self.get_nak_flag()))
        print("\tGET: {}".format(self.get_get_flag()))
        print("\tDAT: {}".format(self.get_dat_flag()))
        print("\tFIN: {}".format(self.get_fin_flag()))
        print("\tCHK: {}".format(self.get_chk_flag()))
        print("\tENC: {}".format(self.get_enc_flag()))
        print("\nData:")
        print("\t{}".format(self.get_data()))

    def payload_to_bytes(self):
        """ Wrapper for the `__get_payload_bytes()` method. """
        return self.__get_payload_bytes()

    def to_bytes(self):
        """ Returns the class contents as a sequence of bytes. """
        flagsBitString = "{}{}{}{}{}{}{}0".format(self.__ACKFlag, self.__NAKFlag, 
                self.__GETFlag, self.__DATFlag, self.__FINFlag, self.__CHKFlag, 
                self.__ENCFlag)

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("Flag bit string: {}".format(flagsBitString))
            print("Flag bytes: {}".format(self.__bitstring_to_bytes(
                    flagsBitString)))

        binPacket = (self.__sequenceNumber.to_bytes(2, 'big') + \
                self.__acknowledgementNumber.to_bytes(2, 'big') + \
                self.__checksum.to_bytes(2, 'big') + \
                self.__bitstring_to_bytes(flagsBitString) + \
                self.__packetVersion.to_bytes(1, 'big') + \
                self.__data.encode()).ljust(RUSHBPacket.get_max_packet_size(), 
                        b"\x00")

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(__filename__)
            print("Packet length: {}".format(len(binPacket)))

        return binPacket

    def create_checksum_from_data(self, onesComplement: bool):
        """ Creates a checksum based on the data it has 
        
        ARGS:
        - onesComplement: Flag to indicate whether to perform the 1's complement
                at the end.

        RETURNS:
        - On success, method returns an integer of the checksum.
        """
        packetBytes = self.__get_payload_bytes()

        baseBitsAsInt = 0

        numBytes = len(packetBytes)
        bytesProcessedCounter = 0

        listOfReversedIntegers: List[int] = [baseBitsAsInt]
        
        while bytesProcessedCounter < numBytes:
            # Get the bits
            bits = bytes(reversed(packetBytes[
                    bytesProcessedCounter:bytesProcessedCounter+2]))

            # Convert bits to a bitstring
            bitsAsInt = self.__bytes_to_integer(bytesRaw=bits)

            # print("bitstring: {}".format(hex(bitsAsInt)))
            baseBitsAsInt = self.__ones_comp_add_16bit(num1=baseBitsAsInt, 
                    num2=bitsAsInt)
                    
            
            bytesProcessedCounter += 2


        # Take the ones complement of the bits
        baseBitsAsInt = ~baseBitsAsInt & 0xffff

        return baseBitsAsInt

    # ? PRIVATE METHODS --------------------------------------------------------

    def __get_payload_bytes(self):
        """ Returns the payload encoded as bytes, padded with zeros if required. 
        """
        return self.__data.encode().ljust(RUSHBPacket.get_max_payload_size(), 
                b"\x00")

    def __bitstring_to_bytes(self, s: str):
        """ Convert a bit string to bytes. """
        v = int(s, 2)
        b = bytearray()
        while v:
            b.append(v & 0xff)
            v >>= 8
        return bytes(b[::-1])

    def __init_from_bytes(self, bytesRaw: bytes):
        """ Initialises the packet from a series of bytes. 
        
        Intended as a means to convert packets recieved via the socket interface
            into a more accessible/usable format.

        ARGS:
        - bytesRaw: The sequence of bytes we wish to extract parameters from.
                This method expects the bytes sequence to be arrange as 
                described above.
        """
        try:
            # Get the sequence number
            self.__sequenceNumber = self.__bytes_to_integer(bytesRaw[0:2])
            self.__acknowledgementNumber = self.__bytes_to_integer(
                    bytesRaw[2:4])
            
            # TODO We will need to change the checksum at some point.
            self.__checksum = self.__bytes_to_integer(bytesRaw[4:6])

            # Get the next two bytes, convert them to binary, and pad with zeros
            #   
            binByteOne = str(bin(bytesRaw[6])).replace("0b", "").zfill(8)
        
            # Retrieve all the flags from this byte (there are 7 of them)

            # Acknowledge
            self.__ACKFlag = int(binByteOne[0])
            
            # Not-Acknowledge
            self.__NAKFlag = int(binByteOne[1])

            # Get
            self.__GETFlag = int(binByteOne[2])

            # Data
            self.__DATFlag = int(binByteOne[3])

            # Finished
            self.__FINFlag = int(binByteOne[4])

            # Packet Integrity
            self.__CHKFlag = int(binByteOne[5])

            # Encoding (?)
            self.__ENCFlag = int(binByteOne[6])
            
            # Version number (will be an integer)
            self.__packetVersion = bytesRaw[7]

            # Data (ASCII)
            self.__data = bytesRaw[8:].decode()

            self.__packetInitStatus = RUSHBPacketInitState.PACKET_INIT_OK
        except Exception as e:
            self.__packetInitStatus = RUSHBPacketInitState.PACKET_INIT_FAILED
            
            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                exc_type, exc_obj, exc_tb = sys.exc_info()
                geh = GenericErrorHandler()
                geh.debug_print_error(filename=__filename__,
                        className=self.__classname__,
                        methodName="__init_from_bytes",
                        lineNum=exc_tb.tb_lineno,   # type: ignore
                        exception=e)
        

    def __init_from_dict(self, inputDict: dict):
        """ Initialises the packet from a dictionary. 
        
        Intended to be used as a means for the server to generate packets 
            easier.

        The input dict should be of the form show below:
        ```
        inputDict = {
            sequence_number: int,
            acknowledgement_number: int,
            checksum: int,
            ack_flag: int,
            nak_flat: int,
            get_flag: int,
            dat_flag: int,
            fin_flag: int,
            chk_flag: int,
            enc_flag: int,
            packet_version: int,
            data: str,
        }
        ```

        ARGS:
        - inputDict: A dictionary of the form described above.
        """
        try:
            self.__sequenceNumber = inputDict['sequence_number']
            self.__acknowledgementNumber = inputDict['acknowledgement_number']
            self.__checksum = inputDict['checksum']
            self.__ACKFlag = inputDict['ack_flag']
            self.__NAKFlag = inputDict['nak_flag']
            self.__GETFlag = inputDict['get_flag']
            self.__DATFlag = inputDict['dat_flag']
            self.__FINFlag = inputDict['fin_flag']
            self.__CHKFlag = inputDict['chk_flag']
            self.__ENCFlag = inputDict['enc_flag']
            self.__packetVersion = inputDict['packet_version']
            self.__data = inputDict['data']

            self.__packetInitStatus = RUSHBPacketInitState.PACKET_INIT_OK
        except Exception as e:
            self.__packetInitStatus = RUSHBPacketInitState.PACKET_INIT_FAILED
            
            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                exc_type, exc_obj, exc_tb = sys.exc_info()
                geh = GenericErrorHandler()
                geh.debug_print_error(filename=__filename__,
                        className=self.__classname__,
                        methodName="__init_from_dict",
                        lineNum=exc_tb.tb_lineno,   # type: ignore
                        exception=e)

    # ? STATIC METHODS ---------------------------------------------------------

    @staticmethod
    def get_max_packet_size():
        """ Maximum packet size (header + payload) in bytes """
        return 1472

    @staticmethod
    def get_max_payload_size():
        """ Maximum payload size in bytes (1472 - 8)"""
        return 1464

    @staticmethod
    def validate_checksum(payloadBytes: bytes, checksum: int):
        """ Validates the checksum of the packet. 
        
        RETURNS:
        - On success (i.e. the checksum is valid), method returns `True`,
                otherwise method returns `False`.
        """
        debugPrinter = DebugLinePrinter()

        packetBytes = payloadBytes

        baseBitsAsInt = checksum

        if __DEBUG_MODE_ENABLED__:
            debugPrinter.debug_message_line_print(__filename__)
            print("Binary bitstring to validate: {}".format(
                    hex(baseBitsAsInt)))

        numBytes = len(packetBytes)
        bytesProcessedCounter = 0
        while bytesProcessedCounter < numBytes:
            # Get the bits
            bits = bytes(reversed(packetBytes[
                    bytesProcessedCounter:bytesProcessedCounter+2]))

            # Convert bits to a bitstring
            bitsAsInt = RUSHBPacket.__bytes_to_integer(bytesRaw=bits)

            baseBitsAsInt = RUSHBPacket.__ones_comp_add_16bit(num1=baseBitsAsInt, 
                    num2=bitsAsInt)
               
            bytesProcessedCounter += 2

        if __DEBUG_MODE_ENABLED__:
            debugPrinter.debug_message_line_print(__filename__)
            print("Output bits: {}".format(hex(baseBitsAsInt)))

        if baseBitsAsInt != 0xffff:
            return False
        return True

    @staticmethod
    def __bytes_to_integer(bytesRaw: bytes):
        """ Converts a sequence of bytes to an integer. """
        binaryString = RUSHBPacket.__byte_to_binary_string(bytesRaw=bytesRaw)
        
        # Convert the binary string to an integer
        return int(binaryString, 2)

    @staticmethod
    def __byte_to_binary_string(bytesRaw: bytes):
        """ Converts a given sequence of bytes to a binary string. """
        binaryString = ''
        for byte in bytesRaw:
            binByteOne = str(bin(byte)).replace("0b", "").zfill(8)
            binaryString += binByteOne
        return binaryString

    @staticmethod
    def __ones_comp_add_16bit(num1: int, num2: int):
        """ Performs 16 bit addition and performs 1's complement on the result. 
        """
        MOD = 1 << 16
        result = num1 + num2
        return result if result < MOD else (result+1) % MOD
    
    # ? PRECONDITIONS ----------------------------------------------------------

    @staticmethod
    def __init_from_dict_precondition(inputDict):
        assert isinstance(inputDict, dict), \
                    "inputDict must be a valid dictionary"
    
    @staticmethod
    def __init__from_bytes_precondition(bytesRaw):
        assert isinstance(bytesRaw, bytes), \
                    "bytesRaw must be valid bytes object"

    @staticmethod
    def __set_acknowledgement_number_precondition(newAckNum):
        assert isinstance(newAckNum, int) and newAckNum >= 0, \
                "newAckNum must be a valid integer"