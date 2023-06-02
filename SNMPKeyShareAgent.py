import socket
from SNMPKeySharePDU import SNMPKeySharePDU
from MIB import *
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
    def __init__(self, timeout=5, mib=None):
        self.timeout = timeout
        self.last_request_time = {}
        self.start_time = time.time()
        self.mib = mib if mib is not None else SNMPKeyShareMIB()  # Use a MIB implementada

    def snmpkeyshare_response(self, P, NW, W, is_set=False):
        if is_set:
            for oid, value in W:
                self.mib.set(oid, value)
        else:
            # Recupera os valores de MIB usando a lista de OIDs
            R = [(oid, self.mib.get(oid)) for oid, _ in W]
            NR = len(R)
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
                response_pdu = self.snmpkeyshare_response(pdu.P, pdu.NW, pdu.W, is_set=True)
                sock.sendto(str(response_pdu).encode(), addr)

            elif pdu.S == 0:  # get
                response_pdu = self.snmpkeyshare_response(pdu.P, pdu.NL, pdu.L, is_set=False)
                sock.sendto(str(response_pdu).encode(), addr)

            else:
                print(f"Tipo de primitiva desconhecido: {pdu.S}")


def main():
    file_path = "config.ini"
    config_parameters = read_config_file(file_path)
    udp_port = int(config_parameters['udp_port'])
    print(f"O agente está a escutar na porta UDP: {udp_port}")
    ip = "127.0.0.1"
    port = udp_port
    agent = SNMPKeyShareAgent()
    agent.serve(ip, port)


if __name__ == "__main__":
    main()
