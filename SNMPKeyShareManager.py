import socket
import time
from SNMPKeySharePDU import SNMPKeySharePDU


class SNMPKeyShareManager:

    def __init__(self, timeout):

        self.timeout = timeout
        self.requests = {}
        self.last_request_time = {}

    def snmpkeyshare_get(self, P, NL, L, agent_ip, agent_port):

        if P in self.last_request_time and (time.time() - self.last_request_time[P]) < self.timeout:
            raise ValueError(
                f"Não é permitido enviar outro pedido com o mesmo P ({P}) durante {self.timeout} segundos.")

        self.last_request_time[P] = time.time()
        pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=1,
                              NL_or_NW=NL, L_or_W=L, NR=0, R=[])

        # Enviar o PDU para o agente utilizando comunicação UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(self.timeout)
            pdu_str = str(pdu)
            udp_socket.sendto(pdu_str.encode(), (agent_ip, agent_port))

            try:
                response_data, _ = udp_socket.recvfrom(1024)
                response_pdu = SNMPKeySharePDU.from_string(
                    response_data.decode())
                return response_pdu
            except socket.timeout:
                print(
                    f"O agente não respondeu no intervalo de tempo {self.timeout} segundos.")
                return None

    def snmpkeyshare_set(self, P, NW, W, agent_ip, agent_port):

        if P in self.last_request_time and (time.time() - self.last_request_time[P]) < self.timeout:
            raise ValueError(
                f"Não é permitido enviar outro pedido com o mesmo P ({P}) durante {self.timeout} segundos.")

        self.last_request_time[P] = time.time()
        pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=2,
                              NL_or_NW=NW, L_or_W=W, NR=0, R=[])

        # Enviar o PDU para o agente usando comunicação UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(self.timeout)
            pdu_str = str(pdu)
            udp_socket.sendto(pdu_str.encode(), (agent_ip, agent_port))

            try:
                response_data, _ = udp_socket.recvfrom(1024)
                response_pdu = SNMPKeySharePDU.from_string(
                    response_data.decode())
                return response_pdu
            except socket.timeout:
                print(
                    f"O agente não respondeu no intervalo de tempo {self.timeout} segundos.")
                return None


timeout = 10  # Escolha um valor apropriado para o tempo limite
manager = SNMPKeyShareManager(timeout)

ip = "127.0.0.1"
port = 161
agent_address = (ip, port)

# Preparando os dados da primitiva snmpkeyshare-get
P = 1
NL = 2
L = [(1, 1), (2, 1)]

# Enviando a primitiva snmpkeyshare-get
get_pdu = manager.snmpkeyshare_get(P, NL, L, ip, port)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
    udp_socket.sendto(str(get_pdu).encode(), agent_address)
    response_data, _ = udp_socket.recvfrom(1024)
    response_pdu = SNMPKeySharePDU.from_string(response_data.decode())

print("Resposta snmpkeyshare-get recebida:")
print(response_pdu)

# Preparando os dados da primitiva snmpkeyshare-set
P = 2
NW = 2
W = [(1, "novo_valor1"), (2, "novo_valor2")]

# Enviando a primitiva snmpkeyshare-set
set_pdu = manager.snmpkeyshare_set(P, NW, W, ip, port)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
    udp_socket.sendto(str(set_pdu).encode(), agent_address)
    response_data, _ = udp_socket.recvfrom(1024)
    response_pdu = SNMPKeySharePDU.from_string(response_data.decode())

print("Resposta snmpkeyshare-set recebida:")
print(response_pdu)
