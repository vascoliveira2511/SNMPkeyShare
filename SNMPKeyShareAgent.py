import datetime
import pickle
import socket
import threading
import configparser
import time

from MIB import *
from SNMPKeySharePDU import SNMPKeySharePDU
from keyMaintenance import generate_matrices, process_Z, generate_key


def read_config_file(file_path):

	"""Lê o ficheiro de configuração e retorna um dicionário com os parâmetros"""

	config = configparser.ConfigParser()
	config.read(file_path)

	parameters = {
		"udp_port": int(config.get("Network", "udp_port")),
		"K": int(config.get("Key Maintenance", "K")),
		"M": config.get("Key Maintenance", "M"),
		"T": int(config.get("Key Maintenance", "T")),
		"V": int(config.get("Key Maintenance", "V")),
		"X": int(config.get("Key Maintenance", "X"))
	}

	return parameters


class SNMPKeyShareAgent:

	"""Classe que representa um agente SNMPKeyShare"""

	def __init__(self, K, M, T, V, X, mib):

		"""Construtor da classe"""

		self.key_update_thread = None

		self.start_time = time.time()
		self.mib = mib if mib is not None else SNMPKeyShareMIB()
		self.running = False
		self.T = T
		self.K = K
		self.M = M
		self.V = V
		self.X = X
		self.Z = generate_matrices(list(map(int, M)), K, use_zs=False)
		self.num_updates = 0
		self.current_key_id = 1
		self.addr = None

		self.set_mib_initial_values()

	def set_mib_initial_values(self):
		
		"""Define os valores iniciais da MIB"""
		self.mib.set("1.4.0", self.T)  # systemIntervalUpdate
		self.mib.set("1.5.0", self.X)  # systemMaxNumberOfKeys
		self.mib.set("1.6.0", self.V)  # systemKeysTimeToLive
		self.mib.set("2.1.0", self.M)  # configMasterKey

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
			process_Z(self.Z)
			self.expire_keys()
			self.update_number_valid_keys()
			time.sleep(self.T)

	def get_id_from_oid(self, oid):
		
		"""Retorna o ID de uma chave a partir do OID"""

		return oid.split(".")[-1]

	def expire_keys(self):
		
		"""Remove as chaves expiradas"""

		current_date = datetime.now().strftime("%Y%m%d")
		current_time = datetime.now().strftime("%H%M%S")

		for entry in self.mib.mib:
			if entry.startswith("3.2.1.1"):
				id = self.get_id_from_oid(entry)
				key_expiration_date = self.mib.get(f"3.2.1.4.{id}")
				key_expiration_time = self.mib.get(f"3.2.1.5.{id}")
				if key_expiration_date < current_date or (key_expiration_date == current_date and key_expiration_time < current_time):
					self.mib.remove_entry_from_dataTableGeneratedKeys(entry)

	def count_number_valid_keys(self):
		
		"""Conta o número de chaves válidas"""

		count = 0
		for entry in self.mib.mib:
			if entry.startswith("3.2.1.1"):
				id = self.get_id_from_oid(entry)
				key_visibility = self.mib.get(f"3.2.1.6.{id}")
				if key_visibility == 1 or key_visibility == 2:
					count += 1
		return count
	
	def update_number_valid_keys(self):
		
		"""Atualiza o número de chaves válidas"""

		self.mib.setAdmin("3.1.0", self.count_number_valid_keys())
		
	def get_uptime(self):
		
		"""Retorna o tempo de atividade do agente"""

		return time.time() - self.start_time
	
	def calculate_key_expiration_date(self):

		"""Calcula a data de expiração de uma chave"""	

		new_date = datetime.now() + timedelta(seconds=self.V)
		return new_date.strftime("%Y%m%d")

	def calculate_key_expiration_time(self):

		"""Calcula o tempo de expiração de uma chave"""

		new_time = datetime.now() + timedelta(seconds=self.V)
		return new_time.strftime("%H%M%S")
	
	def check_limits(self):
		
		"""Verifica se o número de chaves geradas está dentro dos limites"""

		if self.count_number_valid_keys() >= self.mib.get("1.5.0"):
			return False
		else:
			return True

	def generate_and_update_key(self):
		"""Gera e atualiza uma chave"""
		
		if self.check_limits():
			key = generate_key(self.Z, self.num_updates)

			self.num_updates += 1
			key_expiration_date = self.calculate_key_expiration_date()
			key_expiration_time = self.calculate_key_expiration_time()

			return key, key_expiration_date, key_expiration_time
		else:
			raise ValueError(f"O número de chaves geradas ({self.count_number_valid_keys()}) está acima do limite ({self.mib.get('1.5.0')}).")
		
	def get_key_info(self, oid, addr):
		
		"""Retorna a informação de uma chave"""

		id = self.get_id_from_oid(oid)
		key_visibility = self.mib.get(f"3.2.1.6.{id}")
		if key_visibility == 0:
			raise ValueError(f"A chave com o OID {oid} é invisível.")
		elif key_visibility == 1:
			key_requester = self.mib.get(f"3.2.1.3.{id}")
			if key_requester != addr:
				raise ValueError(f"A chave com o OID {oid} é invisível para o endereço {addr}.")
		else:
			pass

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
					if oid.startswith("3.2.1."):
						try:
							self.get_key_info(oid, self.addr)
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
				else:
					if oid.startswith("3.2.1."):
						try:
							self.get_key_info(oid, self.addr)
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
						if oid.startswith("3.2.1."):
							try:
								oid, value = self.mib.get_next(oid, self.get_id_from_oid(oid))
								L.append((oid, value))
							except ValueError as e:
								R.append((oid, e))
								NR += 1
						else:
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
					try:
						key, key_expiration_date, key_expiration_time = self.generate_and_update_key()
						oid, value = self.mib.add_entry_to_dataTableGeneratedKeys(self.current_key_id, key, self.addr, key_expiration_date, key_expiration_time, value)
						self.current_key_id += 1
						W.append((oid, value))
					except ValueError as e:
						R.append((oid, e))
						NR += 1
				else:
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
				data, self.addr = sock.recvfrom(1024)

				# Usar pickle para desserializar os dados
				pdu = pickle.loads(data)

				response_pdu = self.snmpkeyshare_response(pdu.P, pdu.NL_or_NW, pdu.L_or_W, pdu.Y)

				# Usar pickle para serializar o response_pdu
				response_pdu = pickle.dumps(response_pdu)

				sock.sendto(response_pdu, self.addr)
		except KeyboardInterrupt:
			print("O agente foi terminado pelo utilizador.")


def main():

	"""Função principal"""

	file_path = "config.ini"
	config_parameters = read_config_file(file_path)
	udp_port = int(config_parameters['udp_port'])
	K = int(config_parameters['K'])
	M = config_parameters['M']
	T = int(config_parameters['T'])
	V = int(config_parameters['V'])
	X = int(config_parameters['X'])
	ip = "127.0.0.1"
	port = udp_port
	agent = SNMPKeyShareAgent(K, M, T, V, X, None)
	agent.start_key_update_thread()
	agent.serve(ip, port)
	agent.stop_key_update_thread()


if __name__ == "__main__":
	main()
