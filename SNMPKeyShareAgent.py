import socket
from SNMPKeySharePDU import SNMPKeySharePDU
from snmpKeyShareMIB import *
import time
import configparser


def read_config_file(file_path):
    """
    Lê o arquivo de configuração e retorna um dicionário com os parâmetros de configuração.
    """
    config = configparser.ConfigParser()
    config.read(file_path)

    # Extraindo os parâmetros de configuração
    parameters = {
        "udp_port": config.get("Network", "udp_port"),
        # Adicione aqui outros parâmetros de configuração conforme necessário
    }

    return parameters


class SNMPKeyShareAgent:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.last_request_time = {}
        self.start_time = time.time()

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


def main():
    file_path = "config.ini"
    config_parameters = read_config_file(file_path)
    udp_port = config_parameters['udp_port']
    print(f"O agente está a escutar na porta UDP: {udp_port}")
    ip = "127.0.0.1"
    port = udp_port
    agent = SNMPKeyShareAgent()
    agent.serve(ip, port)


if __name__ == "__main__":
    main()
