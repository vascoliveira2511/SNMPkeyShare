import datetime
import pickle
import socket
import threading
import configparser
import time

from MIB import *
from SNMPKeySharePDU import SNMPKeySharePDU
from keyMaintenance import generate_random_K, generate_random_M_string, generate_matrices, process_Z, generate_key

K = generate_random_K()
M_string = generate_random_M_string(K)
M = list(map(int, M_string))


def read_config_file(file_path):

	"""Lê o ficheiro de configuração e retorna um dicionário com os parâmetros"""

	config = configparser.ConfigParser()
	config.read(file_path)

	parameters = {
		"udp_port": config.get("Network", "udp_port"),
	}

	return parameters


class SNMPKeyShareAgent:

	"""Classe que representa um agente SNMPKeyShare"""

	def __init__(self, timeout=5, mib=None):

		"""Construtor da classe"""

		self.key_update_thread = None
		self.timeout = timeout
		self.start_time = time.time()
		self.mib = mib if mib is not None else SNMPKeyShareMIB()
		self.running = False
		self.Z = generate_matrices(M, K, use_zs=False)
		self.num_updates = 0
		self.T = 10000

	def start_key_update_thread(self):

		"""Inicia a thread que atualiza as chaves"""

		self.running = True
		self.key_update_thread = threading.Thread(target=self.key_update_loop)
		self.key_update_thread.start()

	def stop_key_update_thread(self):

		"""Para a thread que atualiza as chaves"""

		self.running = False
		self.key_update_thread.join()

	def key_update_loop(self):

		"""Loop que atualiza as chaves"""

		while self.running:
			process_Z(self.Z, self.T)
			"""	
			self.generate_and_update_key()
			print("Key updated")
			self.expire_keys()
			"""

	def get_uptime(self):
		
		"""Retorna o tempo de atividade do agente"""

		return time.time() - self.start_time

	def snmpkeyshare_response(self, P, NL_or_NW, L_or_W, Y):

		"""Processa um PDU SNMPKeyShare e retorna a resposta"""

		# L = GET
		# W = SET

		R = []
		NR = 0

		# Processar o PDU recebido e gerar a resposta

		# Se o PDU recebido for um snmpkeyshare-get

		if Y == 1:
			L = []
			for pair in L_or_W:
				oid, n = pair
				if n == 0:
					try:
						value = self.mib.get(oid)
						L.append((oid, value))
					except ValueError as e:
						R.append((oid, e))
						NR += 1
				else:
					try:
						value = self.mib.get(oid)
						L.append((oid, value))
					except ValueError as e:
						R.append((oid, e))
						NR += 1
					for i in range(n):
						try:
							oid, value = self.mib.get_next(oid)
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
			for pair in L_or_W:
				oid, value = pair
				if oid == "3.2.1.6.0":
					oid, value = self.mib.add_entry_to_dataTableGeneratedKeys(value)
					W.append((oid, value))
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

		"""Inicia o agente SNMPKeyShare"""

		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind((ip, port))

		print(f"Agente SNMPKeyShare a ouvir no endereço {ip}:{port}")

		try:
			while True:
				data, addr = sock.recvfrom(1024)

				# Usar pickle para desserializar os dados
				pdu = pickle.loads(data)

				response_pdu = self.snmpkeyshare_response(pdu.P, pdu.NL_or_NW, pdu.L_or_W, pdu.Y)

				# Usar pickle para serializar o response_pdu
				response_pdu = pickle.dumps(response_pdu)

				sock.sendto(response_pdu, addr)
		except KeyboardInterrupt:
			print("O agente foi terminado pelo utilizador.")


def main():

	"""Função principal"""

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
