import socket
import threading
import time
import configparser
from SNMPKeySharePDU import SNMPKeySharePDU
from MIB import *

K = generate_random_K()
M_string = generate_random_M_string(K)
M = list(map(int, M_string))

def read_config_file(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)

    parameters = {
        "udp_port": config.get("Network", "udp_port"),
    }

    return parameters

class SNMPKeyShareAgent:
    def __init__(self, timeout=5, mib=None):
        self.timeout = timeout
        self.start_time = time.time()
        self.mib = mib if mib is not None else SNMPKeyShareMIB()
        self.running = False
        self.Z = generate_matrices(M, K, use_zs=False)  # substituir com seus parâmetros
        self.num_updates = 0
        self.T = 10000  

    def start_key_update_thread(self):
        self.running = True
        self.key_update_thread = threading.Thread(target=self.key_update_loop)
        self.key_update_thread.start()

    def stop_key_update_thread(self):
        self.running = False
        self.key_update_thread.join()

    def key_update_loop(self):
        while self.running:
            process_Z(self.Z, self.T)
            self.num_updates += 1  
            self.generate_and_update_key()

    def generate_and_update_key(self):
        C = generate_key(self.Z, self.num_updates)
        print("\nChave gerada C:")
        print(C)
        key_id = self.num_updates
        entry = DataTableGeneratedKeysEntry(key_id)
        entry.set("1.3.6.1.2.1.3.2.1.2", C)
        self.mib.add_entry(entry)
        self.mib.set("1.3.6.1.2.1.3.1", self.num_updates)  

    def get_uptime(self):
        return time.time() - self.start_time

    def snmpkeyshare_response(self, P, NW, W, is_set=False):
        if is_set:
            for oid, value in W:
                self.mib.set(oid, value)
        else:
            R = [(oid, self.mib.get(oid)) for oid, _ in W]
            NR = len(R)
            response_pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=0, NL_or_NW=NW, L_or_W=W, NR=NR, R=R)
            return response_pdu

    def serve(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))

        print(f"Agente SNMPKeyShare a ouvir no endereço {ip}:{port}")

        while True:
            data, addr = sock.recvfrom(1024)
            pdu = SNMPKeySharePDU.from_string(data.decode())
            print(f"Recebido PDU de {addr}: {pdu}")

            if pdu.S == 1:  
                response_pdu = self.snmpkeyshare_response(pdu.P, pdu.NW, pdu.W, is_set=True)
                sock.sendto(str(response_pdu).encode(), addr)

            elif pdu.S == 0:  
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
    agent.start_key_update_thread()
    agent.serve(ip, port)
    agent.stop_key_update_thread()

if __name__ == "__main__":
    main()
