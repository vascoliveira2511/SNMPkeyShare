import socket
from SNMPKeySharePDU import SNMPKeySharePDU


class SNMPKeyShareAgent:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.last_request_time = {}

    def snmpkeyshare_response(self, P, NW, W, is_set=False):
        if is_set:
            # Processamento do pedido snmpkeyshare-set e atualização da MIB.
            pass

        # Processamento do pedido snmpkeyshare-get e obtenção dos valores da MIB.
        NR = 1
        R = [(0, 0)]

        response_pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=0,
                                       NL_or_NW=NW, L_or_W=W, NR=NR, R=R)
        return response_pdu

    def serve(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))

        print(f"Agente SNMPKeyShare a ouvir no endereço {ip}:{port}")

        while True:
            data, addr = sock.recvfrom(1024)
            pdu = SNMPKeySharePDU.from_string(data.decode())
            print(f"Recebido PDU de {addr}: {pdu}")

            if pdu.S == 1:  # set
                # Implementar a lógica de processamento de primitivas set aqui
                pass

            elif pdu.S == 0:  # get
                # Implementar a lógica de processamento de primitivas get aqui
                pass

            else:
                print(f"Tipo de primitiva desconhecido: {pdu.S}")


ip = "127.0.0.1"
port = 12345

agent = SNMPKeyShareAgent()
agent.serve(ip, port)
