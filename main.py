import socket
import time
from queue import PriorityQueue

class TCPSegment:
    ACK_TIMEOUT = 0.01

    def __init__(self, seq_number: int, ack_number: int, data: bytes):
        self.seq_number = seq_number
        self.ack_number = ack_number
        self.data = data
        self.acknowledged = False
        self._sending_time = time.time()

    def dump(self) -> bytes:
        seq = self.seq_number.to_bytes(8, "big")
        ack = self.ack_number.to_bytes(8, "big")
        return seq + ack + self.data

    def update_sending_time(self, sending_time=None):
        self._sending_time = sending_time if sending_time is not None else time.time()

    @staticmethod
    def load(data: bytes) -> 'TCPSegment':
        seq = int.from_bytes(data[:8], "big")
        ack = int.from_bytes(data[8:16], "big", signed=False)
        return TCPSegment(seq, ack, data[16:])

    @property
    def expired(self):
        return not self.acknowledged and (time.time() - self._sending_time > self.ACK_TIMEOUT)

    def __len__(self):
        return len(self.data)

    def __lt__(self, other):
        return self.seq_number < other.seq_number

    def __eq__(self, other):
        return self.seq_number == other.seq_number


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.max_data_sz = 1024
        self.window_sz = 4096
        self.max_lag = 64

        self._sent_bytes_cnt = 0
        self._delivered_bytes_cnt = 0
        self._received_bytes_cnt = 0
        self._send_window = PriorityQueue()
        self._recv_window = PriorityQueue()
        self._buffer = bytes()

    def recv(self, data_sz: int) -> bytes:
        data = bytes()
        while len(data) < data_sz:
            right_border = min(data_sz, len(self._buffer))
            data += self._buffer[:right_border]
            self._buffer = self._buffer[right_border:]
            if len(data) < data_sz:
                self._receive_segment()
        return data

    def _receive_segment(self, timeout: float = None) -> bool:
        self.udp_socket.settimeout(timeout)
        try:
            segment = TCPSegment.load(self.recvfrom(self.max_data_sz + 16))
        except socket.error:
            return False
        if len(segment):
            self._recv_window.put((segment.seq_number, segment))
            self._shift_recv_window()
        if segment.ack_number > self._delivered_bytes_cnt:
            self._delivered_bytes_cnt = segment.ack_number
            self._shift_send_window()
        return True

    def send(self, data: bytes) -> int:
        sent_data_len = 0
        lag = 0
        while (lag < self.max_lag) and (data or self._delivered_bytes_cnt < self._sent_bytes_cnt):
            if (self._sent_bytes_cnt - self._delivered_bytes_cnt <= self.window_sz) and data:
                sent_length = self._send_segment(TCPSegment(self._sent_bytes_cnt,
                                                            self._received_bytes_cnt,
                                                            data[: min(self.max_data_sz, len(data))]))
                data = data[sent_length:]
                sent_data_len += sent_length
            else:
                if self._receive_segment(TCPSegment.ACK_TIMEOUT):
                    lag = 0
                else:
                    lag += 1
            self._resend_first_segment()
        return sent_data_len

    def _send_segment(self, segment: TCPSegment) -> int:
        sent_length = self.sendto(segment.dump()) - 16

        if segment.seq_number == self._sent_bytes_cnt:
            self._sent_bytes_cnt += sent_length
        elif segment.seq_number > self._sent_bytes_cnt:
            raise ValueError()
        if len(segment):
            segment.data = segment.data[:sent_length]
            segment.update_sending_time()

            self._send_window.put((segment.seq_number, segment))
        return sent_length

    def _shift_recv_window(self):
        first_segment = None
        while not self._recv_window.empty():
            _, first_segment = self._recv_window.get()
            if first_segment.seq_number < self._received_bytes_cnt:
                first_segment.acknowledged = True
            elif first_segment.seq_number == self._received_bytes_cnt:
                self._buffer += first_segment.data
                self._received_bytes_cnt += len(first_segment)
                first_segment.acknowledged = True
            else:
                self._recv_window.put((first_segment.seq_number, first_segment))
                break
        if first_segment is not None:
            self._send_segment(TCPSegment(self._sent_bytes_cnt, self._received_bytes_cnt, bytes()))

    def _shift_send_window(self):
        while not self._send_window.empty():
            _, first_segment = self._send_window.get()
            if first_segment.seq_number >= self._delivered_bytes_cnt:
                self._send_window.put((first_segment.seq_number, first_segment))
                break

    def _resend_first_segment(self):
        if self._send_window.empty():
            return
        _, first_segment = self._send_window.get()
        if first_segment.expired:
            self._send_segment(first_segment)
        else:
            self._send_window.put((first_segment.seq_number, first_segment))

    def close(self):
        super().close()
