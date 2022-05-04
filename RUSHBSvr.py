# Standard libs
from typing import Dict
from typing import Optional

from multiprocessing import Process
from multiprocessing import Queue

import socket
import os

# Local Libs
from RUSHBMultiprocessing import ChildProcessDataTracker
from RUSHBMultiprocessing import ChildProcessType
from RUSHBMultiprocessing import QueueMessage
from RUSHBMultiprocessing import QueueMessageType
from RUSHBMultiprocessing import QueueContainer
from RUSHBMultiprocessing import ClientHandler_ChildProcess
from RUSHBMultiprocessing import PacketReceiver_ChildProcess
from RUSHBMultiprocessing import PacketSender_ChildProcess

from RUSHBHelpers import __DEBUG_MODE_ENABLED__
from RUSHBHelpers import DebugLinePrinter

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBSvr.py'

# * MAIN -----------------------------------------------------------------------

class RUSHBServerParallel(object):
    def __init__(self):
        # Debug printer
        self.__debugPrinter = DebugLinePrinter()

        # Specify that we want to use ipv4 (AF_INET) and the UDP protocol 
        #   (SOCK_DGRAM)
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind to port 0 (will trigger the os to pick an available port)
        self.__sock.bind(('', 0))

        # Keep track of the child processes
        self.__childProcessesDict: Dict[int, ChildProcessDataTracker] = {}

        # Initialise the parent queue (all processes will push to the parent
        #   queue, leaving the parent to wait for requests from its children)
        self.__fromChildToParentQueue: Queue = Queue()

        # Spawn the sender and receiver processes (in that order)
        self.__init_process(processType=ChildProcessType.SENDER_PROCESS)
        self.__init_process(processType=ChildProcessType.RECEIVER_PROCESS)

        # Begin the main loop
        self.main_loop()


    def main_loop(self):
        while True:
            # Wait for input from child processes
            message: QueueMessage = self.__fromChildToParentQueue.get(
                    block=True)
            
            # Determine who the message was from
            tracker = self.__childProcessesDict[message.get_message_from()]

            if __DEBUG_MODE_ENABLED__:
                self.__debugPrinter.debug_message_line_print(__filename__)
                print("\nMessage from: {}".format(tracker.get_pid()))
                print("Process type: {}".format(tracker.get_process_type()\
                        .name))
                print("Client Address: {}".format(
                        tracker.get_client_address()))
                print('Received: {}'.format(
                        message.get_message_type().name))

            if message.get_message_type() == QueueMessageType\
                    .CLIENT_PACKET_TO_SERVER:
                
                if message.get_client_address() == None:
                    raise Exception("Unknown client address: {}".format(
                            message.get_message_from()))

                childProcessExists: bool = False

                # Determine if there is a handler process for this request
                for child in self.__childProcessesDict:
                    currentChild = self.__childProcessesDict[child]
                    if currentChild.get_process_type() == ChildProcessType.\
                            WORKER_PROCESS and \
                            currentChild.get_client_address()[1] == \
                            message.get_client_address()[1]:    # type: ignore
                        childProcessExists = True
                        
                        # Handler exists, send the information that way
                        if __DEBUG_MODE_ENABLED__:
                            self.__debugPrinter.debug_message_line_print(
                                    __filename__)
                            print("\nHandler for {} exists".format(
                                    message.get_client_address()[1])) # type: ignore
                            
                        self.__send_packet_to_worker(queueMessage=message)

                        # Break out of the for loop
                        break
                
                if not childProcessExists:
                    # Child process does not exist, go ahead and create new
                    #   client.
                    if __DEBUG_MODE_ENABLED__:
                        self.__debugPrinter.debug_message_line_print(
                                __filename__)
                        print("\nHandler for {} does NOT exist".format(
                                message.get_client_address()[1])) # type: ignore

                    tracker = self.__init_process(
                            processType=ChildProcessType.WORKER_PROCESS,
                            clientAddress=message.get_client_address()) # type: ignore
                    
                    # Send the message to the client address
                    self.__send_packet_to_worker(queueMessage=message)


            elif message.get_message_type() == QueueMessageType\
                    .SERVER_PACKET_TO_CLIENT:
                # Set the corresponding client address to the message
                message.set_client_address(tracker.get_client_address())

                # Send a packet to the client
                self.__send_packet_to_client(queueMessage=message)
            
            elif message.get_message_type() == QueueMessageType.\
                    CHILD_PROCESS_FINISHED:
                self.__join_process(queueMessage=message)

    def __send_packet_to_worker(self, queueMessage: QueueMessage):
        for pid in self.__childProcessesDict:
            currentChild = self.__childProcessesDict[pid]

            if currentChild.get_process_type() == ChildProcessType.\
                    WORKER_PROCESS and \
                    currentChild.get_client_address()[1] == \
                    queueMessage.get_client_address()[1]:   # type: ignore
                if __DEBUG_MODE_ENABLED__:
                    self.__debugPrinter.debug_message_line_print(__filename__)
                    print("\nSending message to worker: {}".format(pid))
                
                currentChild.get_to_child_queue().put(queueMessage)

                # Break out of the for loop
                return

    def __send_packet_to_client(self, queueMessage: QueueMessage):
        """ Sends a packet to a destination. """
        for pid in self.__childProcessesDict:
            
            currentChild = self.__childProcessesDict[pid]
            
            if currentChild.get_process_type() == \
                    ChildProcessType.SENDER_PROCESS:

                if __DEBUG_MODE_ENABLED__:
                    self.__debugPrinter.debug_message_line_print(
                            __filename__)
                    print("Sending message to client: {}".format(
                            queueMessage.get_client_address()[1])) # type: ignore
                
                currentChild.get_to_child_queue().put(queueMessage)
                # Break out of for loop
                return 
    
    def __join_process(self, queueMessage: QueueMessage):
        """ Joins a specified child process to main. """
        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(
                    __filename__)
            print("Process {} requesting join".format(queueMessage\
                    .get_message_from()))
            
        processToJoin = queueMessage.get_message_from()

        # Join the process
        self.__childProcessesDict[processToJoin].get_process_handle().join()
        
        # Remove the process from the child processes dict
        result = self.__childProcessesDict.pop(processToJoin, None)

        if result != None:
            pass
        else:
            raise Exception("Child process {} does not exist!".format(
                    processToJoin))


    def __init_process(self, processType: ChildProcessType, 
            clientAddress: Optional[tuple]=None):
        # Each child process gets a unique queue to receive messages from the 
        #   parent
        fromParentToChildQueue = Queue()

        newChildQueueContainer = QueueContainer(
                fromProcessQueue=fromParentToChildQueue,
                toProcessQueue=self.__fromChildToParentQueue,
                socket=self.__sock)
        
        if processType == ChildProcessType.SENDER_PROCESS:
            p = Process(target=sender_child_process_starter, 
                    args=(newChildQueueContainer,))
        elif processType == ChildProcessType.RECEIVER_PROCESS:
            p = Process(target=receiver_child_process_starter, 
                    args=(newChildQueueContainer,))
        elif processType == ChildProcessType.WORKER_PROCESS:
            p = Process(target=handler_child_process_starter, 
                    args=(newChildQueueContainer,))
        else:
            raise Exception("Unknown process type: {}".format(processType))
        
        
        # Start the sender child process
        p.start()

        if clientAddress != None:
            address = clientAddress
        else:
            address = ()

        temp = ChildProcessDataTracker(
                toChildQueue=fromParentToChildQueue,
                process=p,
                processType=processType,
                clientAddress=address)

        if p.pid == None:
            raise Exception("Error starting process: {}".format(processType))

        self.__childProcessesDict[p.pid] = temp # type: ignore

        if __DEBUG_MODE_ENABLED__:
            self.__debugPrinter.debug_message_line_print(
                    __filename__)
            print("New worker client address: {}".format(temp.get_client_address()))

        return temp

def sender_child_process_starter(queueContainer: QueueContainer):
    """ Function to start the `sender` child process. """
    senderProcess = PacketSender_ChildProcess(queueContainer=queueContainer)
    # Begin the child process main loop
    senderProcess.main_loop()

def receiver_child_process_starter(queueContainer: QueueContainer):
    """ Function to start the `receiver` child process. """
    recverProcess = PacketReceiver_ChildProcess(queueContainer=queueContainer)
    
    # Begin the child process main loop
    recverProcess.main_loop()

def handler_child_process_starter(queueContainer: QueueContainer):
    """ Function to start the `handler` child process. """
    handlerProcess = ClientHandler_ChildProcess(queueContainer=queueContainer)
    
    # Begin the child process main loop
    handlerProcess.main_loop()

if __name__ == '__main__':
    # Run the server
    RUSHBServerParallel()