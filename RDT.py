import Network
import argparse
import time
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()

        #and check if the same
        return checksum_S != computed_checksum_S


class Packet_2(Packet):
    flag_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32
    full_length = flag_num_S_length + length_S_length + checksum_length

    def __init__(self, flag):
        self.flag = flag

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet_2.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        flag = int(byte_S[Packet_2.length_S_length : Packet_2.length_S_length+Packet_2.flag_num_S_length])
        return self(flag)


    def get_byte_S(self):
        #convert flag of a byte field of flag_num_S_length bytes
        flag_num_S = str(self.flag).zfill(self.flag_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(flag_num_S) + self.checksum_length).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5(str(length_S+flag_num_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + flag_num_S + checksum_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet_2.length_S_length]
        flag_num_S = byte_S[Packet_2.length_S_length : Packet_2.flag_num_S_length+Packet_2.flag_num_S_length]
        checksum_S = byte_S[Packet_2.length_S_length+Packet_2.flag_num_S_length :]
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+flag_num_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

    ## for RDT 2.1
    def is_nak(self, flag):
        if flag == 0:
            return True
        return False

    def is_ack(self, flag):
        if flag == 1:
            return True
        return False


    ## for RDT 3.0
    def is_ack0(self, flag):
        if flag == 0:
            return True
        return False

    def is_ack1(self, flag):
        if flag == 1:
            return True
        return False


class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    state_send = 0
    check_sum = 32
    rcv_state = 0
    ## buffer of bytes read from network
    byte_buffer = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            

    def rdt_2_1_send(self, msg_S):

        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())

        if self.state_send == 0:
            sending = True
            while sending:
                bytes_S = self.network.udt_receive()
                if len(bytes_S) == Packet_2.full_length:
                    pac = Packet_2.from_byte_S(bytes_S)
                    if pac.corrupt(bytes_S) or pac.is_nak(pac.flag):
                        self.network.udt_send(p.get_byte_S())
                    elif not pac.corrupt(bytes_S) and pac.is_ack(pac.flag):
                        self.seq_num -= 1
                        self.state_send = 1
                        sending = False

        elif self.state_send == 1:
            sending = True
            while sending:
                bytes_S = self.network.udt_receive()
                if len(bytes_S) == Packet_2.full_length:
                    pac = Packet_2.from_byte_S(bytes_S)
                    if pac.corrupt(bytes_S) or pac.is_nak(pac.flag):
                        self.network.udt_send(p.get_byte_S())
                    elif not pac.corrupt(bytes_S) and pac.is_ack(pac.flag):
                        self.seq_num += 1
                        self.state_send = 0
                        sending = False

    def rdt_2_1_receive(self):
        ret_S = None

        while (True):
            byte_S = None
            while byte_S is None:
                byte_S = self.network.udt_receive()
                if byte_S:
                    self.byte_buffer += byte_S
                    break
                else:
                    continue

            if(len(self.byte_buffer) < Packet.length_S_length):
                sleep(0.5)
                return ret_S #not enough bytes to read packet length
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                sleep(0.5)
                return ret_S #not enough bytes to read the whole packet
            p = Packet.from_byte_S(self.byte_buffer[0:length])

            if self.rcv_state == 0:
                if p.corrupt(p.get_byte_S()):
                    #NAK
                    pac = Packet_2(0)
                    self.network.udt_send(pac.get_byte_S())
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 0:
                    #ACK
                    pac = Packet_2(1)
                    self.network.udt_send(pac.get_byte_S())
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 1:
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    #ACK
                    pac = Packet_2(1)
                    self.network.udt_send(pac.get_byte_S())
                    self.rcv_state = 1

            elif self.rcv_state == 1:
                if p.corrupt(p.get_byte_S()):
                    #NAK
                    pac = Packet_2(0)
                    self.network.udt_send(pac.get_byte_S())
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 1:
                    #ACK
                    pac = Packet_2(1)
                    self.network.udt_send(pac.get_byte_S())
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 0:
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    #ACK
                    pac = Packet_2(1)
                    self.network.udt_send(pac.get_byte_S())
                    self.rcv_state = 0


    def rdt_3_0_send(self, msg_S):

        if self.state_send == 0:
            p = Packet(self.seq_num, msg_S)
            self.network.udt_send(p.get_byte_S())
            timeout = 5
            time_of_last_data = time.time()

            sending = True
            while sending:
                bytes_S = self.network.udt_receive()
                if len(bytes_S) == Packet_2.full_length:
                    pac = Packet_2.from_byte_S(bytes_S)

                    if pac.corrupt(bytes_S) or pac.is_ack0(pac.flag):
                        continue
                    elif time_of_last_data + timeout < time.time():
                        self.network.udt_send(p.get_byte_S())
                        timeout = 5
                        time_of_last_data = time.time()
                    elif not pac.corrupt(bytes_S) or pac.is_ack1(pac.flag):
                        self.seq_num -= 1
                        self.state_send = 1
                        sending = False

        elif self.state_send == 1:
            p = Packet(self.seq_num, msg_S)
            self.network.udt_send(p.get_byte_S())
            timeout = 5
            time_of_last_data = time.time()

            sending = True
            while sending:
                bytes_S = self.network.udt_receive()
                if len(bytes_S) == Packet_2.full_length:
                    pac = Packet_2.from_byte_S(bytes_S)

                    if pac.corrupt(bytes_S) or pac.is_ack1(pac.flag):
                        continue
                    elif time_of_last_data + timeout < time.time():
                        self.network.udt_send(p.get_byte_S())
                        timeout = 5
                        time_of_last_data = time.time()
                    elif not pac.corrupt(bytes_S) or pac.is_ack0(pac.flag):
                        self.seq_num += 1
                        self.state_send = 0
                        #Stop timer??
                        sending = False
        '''
        STATE 0
        wait for packet
            if packet:
                make packet(seq_num = 0, msg, checkSum)
                udt_send
                start timer
                    receive packet
                    while waiting for ACK0 packet
                        if packet is corrupt or ACK1
                            keep waiting
                        timeout
                            udt_send packet again
                            restart timer
                        if packet not corrupt and ACK0
                            go to STATE 1
        STATE 1
        wait for packet
            if packet:
                make packet(seq_num = 1, msg, checkSum)
                udt_send
                start timer
                    receive packet
                    while waiting for ACK1 packet
                        if packet is corrupt or ACK0
                            keep waiting
                        timeout
                            udt_send packet again
                            restart timer
                        if packet not corrupt and ACK1
                            go to STATE 0
        '''

        
    def rdt_3_0_receive(self):
        ret_S = None

        while (True):
            byte_S = None
            while byte_S is None:
                byte_S = self.network.udt_receive()
                if byte_S:
                    self.byte_buffer += byte_S
                    break
                else:
                    continue

            if(len(self.byte_buffer) < Packet.length_S_length):
                sleep(0.5)
                return ret_S #not enough bytes to read packet length
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                sleep(0.5)
                return ret_S #not enough bytes to read the whole packet
            p = Packet.from_byte_S(self.byte_buffer[0:length])

            if self.rcv_state == 0:
                if p.corrupt(p.get_byte_S()) or p.seq_num == 0:
                    #ACK0
                    pac = Packet_2(0)
                    self.network.udt_send(pac.get_byte_S())
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 1:
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    #ACK1
                    pac = Packet_2(1)
                    self.network.udt_send(pac.get_byte_S())
                    self.rcv_state = 1

            elif self.rcv_state == 1:
                if p.corrupt(p.get_byte_S()) or p.seq_num == 1:
                    #ACK1
                    pac = Packet_2(1)
                    self.network.udt_send(pac.get_byte_S())
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 0:
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    #ACK0
                    pac = Packet_2(0)
                    self.network.udt_send(pac.get_byte_S())
                    self.rcv_state = 0
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        