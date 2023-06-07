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


if __name__ == "__main__":
    timeout = 10  # Escolha um valor apropriado para o tempo limite
    manager = SNMPKeyShareManager(timeout)

    ip = "127.0.0.1"
    port = 161
    agent_address = (ip, port)

    while True:
        operation = input("Insira a operação desejada (get ou set): ")
        if operation not in ['get', 'set']:
            print("Operação inválida, tente novamente.")
            continue
        
        P = int(input("Insira o identificador do pedido (P): "))
        
        if operation == 'get':
            NL = int(input("Insira o número de instâncias desejadas (NL): "))
            L = []
            for _ in range(NL):
                instance = int(input("Insira o identificador da instância: "))
                N = int(input("Insira o valor de N: "))
                L.append((instance, N))
            get_pdu = manager.snmpkeyshare_get(P, NL, L, ip, port)
            print("Resposta snmpkeyshare-get recebida:")
            print(get_pdu)
            
        else:  # operation == 'set'
            NW = int(input("Insira o número de instâncias a serem modificadas (NW): "))
            W = []
            for _ in range(NW):
                instance = int(input("Insira o identificador da instância: "))
                value = input("Insira o novo valor para a instância: ")
                W.append((instance, value))
            set_pdu = manager.snmpkeyshare_set(P, NW, W, ip, port)
            print("Resposta snmpkeyshare-set recebida:")
            print(set_pdu)