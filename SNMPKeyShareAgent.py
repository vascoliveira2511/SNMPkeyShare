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

	config = configparser.ConfigParser() # Instanciar o objeto ConfigParser
	config.read(file_path) # Ler o ficheiro de configuração

	parameters = {
		"udp_port": int(config.get("Network", "udp_port")), # Ler o parâmetro udp_port e convertê-lo para inteiro
		"K": int(config.get("Key Maintenance", "K")), # Ler o parâmetro K e convertê-lo para inteiro
		"M": config.get("Key Maintenance", "M"), # Ler o parâmetro M
		"T": int(config.get("Key Maintenance", "T")), # Ler o parâmetro T e convertê-lo para inteiro
		"V": int(config.get("Key Maintenance", "V")), # Ler o parâmetro V e convertê-lo para inteiro
		"X": int(config.get("Key Maintenance", "X")) # Ler o parâmetro X e convertê-lo para inteiro
	}

	return parameters # Retornar o dicionário com os parâmetros


class SNMPKeyShareAgent:

	"""Classe que representa um agente SNMPKeyShare"""

	def __init__(self, K, M, T, V, X, mib):

		"""Construtor da classe"""

		self.key_update_thread = None # Thread que atualiza as chaves

		self.start_time = time.time() # Tempo de início do agente
		self.mib = mib
		self.T = T # Intervalo de tempo entre atualizações
		self.K = K # Tamanho da chave
		self.M = M # Matriz de parâmetros
		self.V = V # Intervalo de tempo para o qual o agente espera por uma resposta
		self.X = X # Número máximo de chaves geradas
		self.Z = generate_matrices(list(map(int, M)), K, use_zs=False) # Matriz Z
		self.load_mib_state()  # Carregar o estado anterior da MIB
		if self.mib is None: # Se não houver um estado anterior da MIB
			self.mib = SNMPKeyShareMIB() # Criar uma nova MIB
			self.set_mib_initial_values() # Definir os valores iniciais da MIB
		else:
			self.mib.setAdmin("1.1.0", int(datetime.now().strftime("%Y%m%d"))) # Obter a data atual
			self.mib.setAdmin("1.2.0", int(datetime.now().strftime("%H%M%S"))) # Obter a hora atual
		self.running = False # Flag que indica se o agente está a correr
		self.num_updates = 0 # Número de atualizações
		self.current_key_id = 1 # ID da chave atual
		self.addr = None # Endereço do gestor

		self.last_request_times = {} # Dicionário que guarda os tempos das últimas requisições

	def save_mib_state(self):
		"""Guarda o estado atual da MIB para um arquivo"""

		with open('mib_state.pkl', 'wb') as f: # Abrir o arquivo mib_state.pkl para escrita
			pickle.dump(self.mib, f) # Serializar a MIB e guardá-la no arquivo

	def load_mib_state(self):
		"""Carrega o estado anterior da MIB de um arquivo, se disponível"""
		try:
			with open('mib_state.pkl', 'rb') as f: # Abrir o arquivo mib_state.pkl para leitura
				self.mib = pickle.load(f) # Deserializar a MIB e guardá-la na variável mib
		except FileNotFoundError: # Se o arquivo não existir
			print("Não foi encontrado nenhum estado da MIB anterior.") # Imprimir uma mensagem de erro

	def set_mib_initial_values(self):
		
		"""Define os valores iniciais da MIB"""
		self.mib.setAdmin("1.3.0", self.K)  # systemKeySize
		self.mib.set("1.4.0", self.T)  # systemIntervalUpdate
		self.mib.set("1.5.0", self.X)  # systemMaxNumberOfKeys
		self.mib.set("1.6.0", self.V)  # systemKeysTimeToLive
		self.mib.set("2.1.0", self.M)  # configMasterKey

	def start_key_update_thread(self):

		"""Inicia a thread que atualiza as chaves"""

		self.running = True # Definir a flag running como True
		self.key_update_thread = threading.Thread(target=self.key_update_loop) # Criar a thread
		self.key_update_thread.start() # Iniciar a thread

	def stop_key_update_thread(self):
		"""Para a thread que atualiza as chaves"""
		self.running = False  # Definir a flag running como False
		self.key_update_thread.join() # Esperar que a thread termine
		self.save_mib_state()  # Salvar o estado da MIB


	def key_update_loop(self):

		"""Loop que atualiza as chaves"""

		while self.running: # Enquanto a flag running for True
			process_Z(self.Z) # Processar a matriz Z
			self.expire_keys() # Remover as chaves expiradas
			self.update_number_valid_keys() # Atualizar o número de chaves válidas
			time.sleep(self.T/1000) # Esperar T milissegundos

	def get_id_from_oid(self, oid):
		
		"""Retorna o ID de uma chave a partir do OID"""

		return oid.split(".")[-1] # Retornar o último elemento do OID

	def expire_keys(self):
		
		"""Remove as chaves expiradas"""

		current_date = int(datetime.now().strftime("%Y%m%d")) # Data atual
		current_time = int(datetime.now().strftime("%H%M%S")) # Hora atual

		mib = self.mib.mib.copy() # Copiar a MIB para uma nova variável
		for entry in mib: # Para cada entrada da MIB
			if entry.startswith("3.2.1.1"): # Se a entrada for uma chave
				ident = self.get_id_from_oid(entry) # Obter o ID da chave
				key_expiration_date = int(self.mib.get(f"3.2.1.4.{ident}")) # Data de expiração da chave
				key_expiration_time = int(self.mib.get(f"3.2.1.5.{ident}")) # Hora de expiração da chave
				if key_expiration_date < current_date or (key_expiration_date == current_date and key_expiration_time < current_time): # Se a chave estiver expirada
					self.mib.remove_entry_from_dataTableGeneratedKeys(entry) # Remover a chave da MIB

	def count_number_valid_keys(self):
		
		"""Conta o número de chaves válidas"""

		count = 0 # Inicializar o contador
		for entry in self.mib.mib: # Para cada entrada da MIB
			if entry.startswith("3.2.1.1"): # Se a entrada for uma chave
				ident = self.get_id_from_oid(entry) # Obter o ID da chave
				key_visibility = self.mib.get(f"3.2.1.6.{ident}") # Visibilidade da chave
				if key_visibility == 1 or key_visibility == 2: # Se a chave for visível
					count += 1 # Incrementar o contador
		return count # Retornar o contador
	
	def update_number_valid_keys(self):
		
		"""Atualiza o número de chaves válidas"""

		self.mib.setAdmin("3.1.0", self.count_number_valid_keys()) # Atualizar o número de chaves válidas
		
	def get_uptime(self):
		
		"""Retorna o tempo de atividade do agente"""

		return time.time() - self.start_time # Retornar o tempo de atividade do agente
	
	def calculate_key_expiration_date(self):

		"""Calcula a data de expiração de uma chave"""	

		new_date = datetime.now() + timedelta(seconds=self.mib.get("1.6.0")) # Calcular a nova data
		return int(new_date.strftime("%Y%m%d")) # Retornar a nova data

	def calculate_key_expiration_time(self):

		"""Calcula o tempo de expiração de uma chave"""

		new_time = datetime.now() + timedelta(seconds=self.mib.get("1.6.0")) # Calcular o novo tempo
		return int(new_time.strftime("%H%M%S")) # Retornar o novo tempo
	
	def check_limits(self):
		
		"""Verifica se o número de chaves geradas está dentro dos limites"""

		if self.count_number_valid_keys() >= self.mib.get("1.5.0"): # Se o número de chaves geradas for maior ou igual ao limite
			return False # Retornar False
		else: # Se o número de chaves geradas for menor que o limite
			return True # Retornar True

	def generate_and_update_key(self):
		"""Gera e atualiza uma chave"""
		
		if self.check_limits(): # Se o número de chaves geradas estiver dentro dos limites
			key = generate_key(self.Z, self.num_updates, self.mib.get("2.2.0"), self.mib.get("2.3.0")) # Gerar a chave

			self.num_updates += 1 # Incrementar o número de atualizações
			key_expiration_date = self.calculate_key_expiration_date() # Calcular a data de expiração da chave
			key_expiration_time = self.calculate_key_expiration_time() # Calcular o tempo de expiração da chave

			return key, key_expiration_date, key_expiration_time # Retornar a chave, a data de expiração e o tempo de expiração
		else: # Se o número de chaves geradas estiver fora dos limites
			raise ValueError(f"O número de chaves geradas ({self.count_number_valid_keys()}) está acima do limite ({self.mib.get('1.5.0')}).") # Lançar uma exceção
		 
	def get_key_info(self, oid, addr): 
		
		"""Retorna a informação de uma chave"""

		ident = self.get_id_from_oid(oid) # Obter o ID da chave
		key_visibility = self.mib.get(f"3.2.1.6.{ident}") # Visibilidade da chave
		if key_visibility == 0: # Se a chave for invisível
			raise ValueError(f"A chave com o OID {oid} é invisível.") # Lançar uma exceção
		elif key_visibility == 1: # Se a chave for visível
			key_requester = self.mib.get(f"3.2.1.3.{ident}") # Endereço do gestor que requisitou a chave
			if key_requester != addr: # Se o endereço do gestor que requisitou a chave for diferente do endereço do gestor que a está a requisitar
				raise ValueError(f"A chave com o OID {oid} é invisível para o endereço {addr}.") # Lançar uma exceção
		else: # Se a chave for pública
			pass # Não fazer nada

	def snmpkeyshare_response(self, P, NL_or_NW, L_or_W, Y):

		"""Processa um PDU SNMPKeyShare e retorna a resposta"""

		# L = GET
		# W = SET

		R = [] # Lista de erros
		NR = 0 # Número de erros

		# Processar o PDU recebido e gerar a resposta

		# Se o PDU recebido for um snmpkeyshare-get

		current_time = time.time() # Tempo atual
		last_request_time = self.last_request_times.get(P) # Tempo da última requisição
		try: 
			if last_request_time is not None and current_time - last_request_time < self.V: # Se o tempo da última requisição for menor que o intervalo de tempo V
				raise ValueError(f"Requisição {P} foi feita há menos de {self.V} segundos") # Lançar uma exceção
			else: # Se o tempo da última requisição for maior que o intervalo de tempo V
				if Y == 1: # Se o PDU recebido for um snmpkeyshare-get

					L = [] # Lista de instâncias e valores associados

					for pair in L_or_W: # Para cada par da lista de instâncias e valores associados
						oid, n = pair # Obter o OID e o número de instâncias
						if n == 0: # Se o número de instâncias for 0
							if oid.startswith("3.2.1."): # Se o OID for de uma chave
								try: 
									self.get_key_info(oid, self.addr) # Verificar se a chave é visível
									value = self.mib.get(oid) # Obter o valor da chave
									L.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
								except ValueError as e: # Se a chave não for visível
									R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
									NR += 1 # Incrementar o número de erros
							else: # Se o OID não for de uma chave
								try: 
									value = self.mib.get(oid) # Obter o valor da instância
									L.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
								except ValueError as e: # Se a instância não existir
									R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
									NR += 1 # Incrementar o número de erros
						else: # Se o número de instâncias for diferente de 0
							if oid.startswith("3.2.1."): # Se o OID for de uma chave
								try:
									self.get_key_info(oid, self.addr) # Verificar se a chave é visível
									value = self.mib.get(oid) # Obter o valor da chave
									L.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
								except ValueError as e: # Se a chave não for visível
									R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
									NR += 1 # Incrementar o número de erros
							else: # Se o OID não for de uma chave
								try:
									value = self.mib.get(oid) # Obter o valor da instância
									L.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
								except ValueError as e: # Se a instância não existir
									R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
									NR += 1 # Incrementar o número de erros
							for i in range(n): # Para cada instância
								if oid.startswith("3.2.1."): # Se o OID for de uma chave
									try:
										self.get_key_info(oid, self.addr) # Verificar se a chave é visível
										oid, value = self.mib.get_next(oid, self.get_id_from_oid(oid)) # Obter o OID e o valor da chave
										L.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
									except ValueError as e: # Se a chave não for visível
										R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
										NR += 1 # Incrementar o número de erros
								else: # Se o OID não for de uma chave
									try:
										oid, value = self.mib.get_next(oid) # Obter o OID e o valor da instância
										L.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
									except ValueError as e: # Se a instância não existir
										R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
										NR += 1 # Incrementar o número de erros
					if NR == 0: # Se o número de erros for 0
						self.last_request_times[P] = current_time # Atualizar o tempo da última requisição
						return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(L), L_or_W=L, NR=NR, R=[]) # Retornar o PDU de resposta
					else: # Se o número de erros for diferente de 0
						self.last_request_times[P] = current_time # Atualizar o tempo da última requisição
						return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(L), L_or_W=L, NR=NR, R=R) # Retornar o PDU de resposta

				# Se o PDU recebido for um snmpkeyshare-set

				elif Y == 2: 

					W = [] # Lista de instâncias e valores associados

					for pair in L_or_W: # Para cada par da lista de instâncias e valores associados
						oid, value = pair # Obter o OID e o valor
						if oid == "3.2.1.6.0": # Se o OID for o da visibilidade de uma chave
							try: 
								key, key_expiration_date, key_expiration_time = self.generate_and_update_key() # Gerar e atualizar uma chave
								oid, value = self.mib.add_entry_to_dataTableGeneratedKeys(self.current_key_id, key, self.addr, key_expiration_date, key_expiration_time, value) # Adicionar a chave à MIB
								self.current_key_id += 1 # Incrementar o ID da chave
								W.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
							except ValueError as e: # Se o número de chaves geradas estiver fora dos limites
								R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
								NR += 1 # Incrementar o número de erros
						else: # Se o OID não for o da visibilidade de uma chave
							try: 
								self.mib.set(oid, value) # Atualizar o valor da instância
								W.append((oid, value)) # Adicionar o par (OID, valor) à lista de instâncias e valores associados
							except ValueError as e: # Se a instância não existir
								R.append((oid, e)) # Adicionar o par (OID, erro) à lista de erros
								NR += 1 # Incrementar o número de erros
					if NR == 0: # Se o número de erros for 0
						self.last_request_times[P] = current_time # Atualizar o tempo da última requisição
						return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(W), L_or_W=W, NR=1, R=[(0, 0)]) # Retornar o PDU de resposta
					else:
						self.last_request_times[P] = current_time # Atualizar o tempo da última requisição
						return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=len(W), L_or_W=W, NR=NR, R=R) # Retornar o PDU de resposta

				# Se o PDU recebido for um snmpkeyshare-response

				elif Y == 0: 
					return None # Retornar None

				# Se o PDU recebido for inválido

				else:
					raise ValueError(f"O valor de Y ({Y}) é inválido.") # Lançar uma exceção
				
		except ValueError as e: # Se o tempo da última requisição for menor que o intervalo de tempo V

			R.append((0, e)) # Adicionar o par (OID, erro) à lista de erros
			NR += 1 # Incrementar o número de erros
			return SNMPKeySharePDU(P=P, Y=0, NL_or_NW=0, L_or_W=[], NR=NR, R=R) # Retornar o PDU de resposta

	def serve(self, ip, port):

		"""Inicia o agente SNMPKeyShare"""

		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Criar o socket UDP
		sock.bind((ip, port)) # Associar o socket ao endereço e porta

		print(f"Agente SNMPKeyShare a ouvir no endereço {ip}:{port}") # Imprimir uma mensagem de sucesso

		while self.running: # Enquanto a flag running for True
					
					if not self.running:  # Verifica se a flag 'running' ainda é True
						break

					data, addr = sock.recvfrom(1024) # Esperar por dados

					if not self.running:  # Verifica se a flag 'running' ainda é True
						break

					self.addr = addr[0]  # Endereço do gestor

					# Usar pickle para desserializar os dados
					pdu = pickle.loads(data)

					response_pdu = self.snmpkeyshare_response(pdu.P, pdu.NL_or_NW, pdu.L_or_W, pdu.Y) # Processar o PDU e gerar a resposta

					# Usar pickle para serializar o response_pdu
					response_pdu = pickle.dumps(response_pdu)

					sock.sendto(response_pdu, addr) # Enviar a resposta para o gestor

def main():

	"""Função principal"""

	file_path = "config.ini" # Caminho para o ficheiro de configuração
	config_parameters = read_config_file(file_path) # Ler o ficheiro de configuração
	udp_port = int(config_parameters['udp_port']) # Porta UDP
	K = int(config_parameters['K']) # Tamanho da chave
	M = config_parameters['M'] # Matriz de parâmetros
	T = int(config_parameters['T']) # Intervalo de tempo entre atualizações 
	V = int(config_parameters['V']) # Intervalo de tempo para o qual o agente espera por uma resposta
	X = int(config_parameters['X']) # Número máximo de chaves geradas
	ip = "127.0.0.1" # Endereço IP
	port = udp_port # Porta UDP
	agent = SNMPKeyShareAgent(K, M, T, V, X, None) # Instanciar o agente
	try: 
		agent.start_key_update_thread() # Iniciar a thread que atualiza as chaves
		agent.serve(ip, port) # Iniciar o agente
	except KeyboardInterrupt:
		agent.stop_key_update_thread() # Parar a thread que atualiza as chaves
		print("O agente foi terminado pelo utilizador.") 


if __name__ == "__main__": # Se o script for executado diretamente
	main() # Executar a função main
