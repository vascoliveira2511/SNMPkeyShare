import datetime
import socket
import threading
import time
import configparser
import pickle
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
        self.Z = generate_matrices(M, K, use_zs=False) 
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
            self.generate_and_update_key()
            print("Key updated")
            self.expire_keys()

    def generate_and_update_key(self):
        if len(self.mib.get("1.3.6.1.2.1.3.2.0")) < self.mib.get("1.3.6.1.2.1.1.0"):  # Check if we have space for more keys
            C = generate_key(self.Z, self.num_updates)
            key_id = self.num_updates
            entry = DataTableGeneratedKeysEntry(key_id)

            # Set key value
            entry.setAdmin("1.3.6.1.2.1.3.2.1.2.0", C)

            print(f"Key {key_id} generated")
            print(f"Key value: {C}")

            # Set KeyRequester
            # The requester could be identified in some way, for instance, by IP address.
            # Here I'll use a placeholder string.
            entry.setAdmin("1.3.6.1.2.1.3.2.1.3.0", "Requester Identification")  

            # Set keyExpirationDate and keyExpirationTime
            ttl = self.mib.get("1.3.6.1.2.1.1.6.0")  # Get the TTL for keys
            expiration_timestamp = time.time() + ttl  # Current time + TTL
            expiration_date = datetime.fromtimestamp(expiration_timestamp).strftime('%Y%m%d')  # Format as YY*104+MM*102+DD
            expiration_time = datetime.fromtimestamp(expiration_timestamp).strftime('%H%M%S')  # Format as HH*104+MM*102+SS
            entry.setAdmin("1.3.6.1.2.1.3.2.1.4.0", int(expiration_date))  
            entry.setAdmin("1.3.6.1.2.1.3.2.1.5.0", int(expiration_time))

            # Set keyVisibility to 0 (not visible) initially
            entry.setAdmin("1.3.6.1.2.1.3.2.1.6.0", 0)

            # Add the entry to the MIB
            self.mib.add_entry(entry)

            # Update the number of valid keys in the MIB
            self.mib.setAdmin("1.3.6.1.2.1.3.1.0", len(self.mib.get("1.3.6.1.2.1.3.2.1")))

            # Increase the number of updates
            self.num_updates += 1


    def expire_keys(self):
            current_time = time.time()
            for entry in self.mib.get("1.3.6.1.2.1.3.2.1"):  # Create a copy of the list to iterate over
                # Assuming keyExpirationDate and keyExpirationTime are in Unix timestamp
               	if current_time > entry.get("1.3.6.1.2.1.3.2.1.4.0") + entry.get("1.3.6.1.2.1.3.2.1.5.0"):
                    self.mib.remove_entry(entry)

    def get_uptime(self):
        return time.time() - self.start_time

    def snmpkeyshare_response(self, P, NL_or_NW, L_or_W, Y):
        
        # L = GET
        # W = SET

        R = []
        NR = 0

        # Processar o PDU recebido e gerar a resposta

        # Se o PDU recebido for um snmpkeyshare-get

        if Y == 1:
            L = []
            for i in range(NL_or_NW):
                oid = L_or_W[i][0]
                try:
                    value = self.mib.get(oid)
                    L.append((oid, value))
                except ValueError as e:
                    R.append((oid, e))
                    NR += 1
            if NR == 0:
                return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(L), L_or_W=L, NR=NR, R=[])
            else:
                return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(L), L_or_W=L, NR=NR, R=R)
                
        # Se o PDU recebido for um snmpkeyshare-set

        elif Y == 2:
            W = []
            for i in range(NL_or_NW):
                oid = L_or_W[i][0]
                value = L_or_W[i][1]
                try:
                    self.mib.set(oid, value)
                    W.append((oid, value))
                except ValueError as e:
                    R.append((oid, e))
                    NR += 1
            if NR == 0:
                return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(W), L_or_W=W, NR=NR, R=[])
            else:
                return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(W), L_or_W=W, NR=NR, R=R)
            
        # Se o PDU recebido for um snmpkeyshare-response

        elif Y == 0:
            return None
        
        # Se o PDU recebido for inválido

        else:
            raise ValueError(f"O valor de Y ({Y}) é inválido.")


    def serve(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))

        print(f"Agente SNMPKeyShare a ouvir no endereço {ip}:{port}")

        while True:
            data, addr = sock.recvfrom(1024)

            # Usar pickle para desserializar os dados
            pdu = pickle.loads(data)

            response_pdu = self.snmpkeyshare_response(pdu.P, pdu.NL_or_NW, pdu.L_or_W, pdu.Y)
            
            # Usar pickle para serializar o response_pdu
            response_pdu = pickle.dumps(response_pdu)

            sock.sendto(response_pdu, addr)

def main():
    file_path = "config.ini"
    config_parameters = read_config_file(file_path)
    udp_port = int(config_parameters['udp_port'])
    ip = "127.0.0.1"
    port = udp_port
    agent = SNMPKeyShareAgent()
    agent.start_key_update_thread()
    agent.serve(ip, port)
    agent.stop_key_update_thread()

if __name__ == "__main__":
    main()
