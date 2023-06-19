import configparser
import pickle
import socket
import time
from SNMPKeySharePDU import SNMPKeySharePDU


def read_config_file(file_path):
	
	"""Lê o ficheiro de configuração e retorna um dicionário com os parâmetros"""

	config = configparser.ConfigParser() # Instanciar o objeto ConfigParser
	config.read(file_path) # Ler o ficheiro de configuração

	parameters = {
		"udp_port": int(config.get("Network", "udp_port")), # Ler o parâmetro udp_port e convertê-lo para inteiro
		"V": int(config.get("Key Maintenance", "V")), # Ler o parâmetro V e convertê-lo para inteiro
	}

	return parameters # Retornar o dicionário com os parâmetros


class SNMPKeyShareManager:

	"""Classe que representa um gestor SNMPKeyShare"""

	def __init__(self, V):

		"""Construtor da classe"""

		self.V = V # Intervalo de tempo para o qual o gestor espera por uma resposta
		self.requests = {} # Dicionário que guarda os pedidos enviados e as respostas recebidas

	def snmpkeyshare_get(self, P, NL, L, agent_ip, agent_port):

		"""Envia um pedido snmpkeyshare-get para o agente SNMPKeyShare"""	

		pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=1, NL_or_NW=NL, L_or_W=L, NR=0, R=[]) # Criar o PDU

		# Enviar o PDU para o agente utilizando comunicação UDP
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:

			udp_socket.settimeout(self.V) # Definir o tempo máximo de espera por uma resposta

			pdu = pickle.dumps(pdu) # Serializar o PDU
			udp_socket.sendto(pdu, (agent_ip, agent_port)) # Enviar o PDU para o agente

			try:
				response_data, _ = udp_socket.recvfrom(1024) # Esperar pela resposta do agente

				response_pdu = pickle.loads(response_data) # Deserializar a resposta

				return response_pdu # Retornar a resposta

			except socket.timeout: # Se o tempo de espera for excedido
				print( 
					f"O agente não respondeu no intervalo de tempo {self.V} segundos.") # Imprimir uma mensagem de erro
				return None # Retornar None

	def snmpkeyshare_set(self, P, NW, W, agent_ip, agent_port):

		"""Envia um pedido snmpkeyshare-set para o agente SNMPKeyShare"""

		pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=2, NL_or_NW=NW, L_or_W=W, NR=0, R=[]) # Criar o PDU

		# Enviar o PDU para o agente usando comunicação UDP
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:

			udp_socket.settimeout(self.V) # Definir o tempo máximo de espera por uma resposta

			pdu = pickle.dumps(pdu) # Serializar o PDU
			udp_socket.sendto(pdu, (agent_ip, agent_port)) # Enviar o PDU para o agente

			try:
				response_data, _ = udp_socket.recvfrom(1024) # Esperar pela resposta do agente

				response_pdu = pickle.loads(response_data) # Deserializar a resposta

				return response_pdu # Retornar a resposta

			except socket.timeout: # Se o tempo de espera for excedido
				print(
					f"O agente não respondeu no intervalo de tempo {self.V} segundos.") # Imprimir uma mensagem de erro
				return None # Retornar None


def main():

	"""Função principal"""

	file_path = "config.ini" # Caminho para o ficheiro de configuração
	config_parameters = read_config_file(file_path) # Ler o ficheiro de configuração
	V = config_parameters['V'] # Intervalo de tempo para o qual o gestor espera por uma resposta
	port = config_parameters['udp_port'] # Porta UDP para a comunicação com o agente
	manager = SNMPKeyShareManager(V) # Instanciar o gestor

	ip = "127.0.0.1" # Endereço IP do agente
	try: 
		while True: # Ciclo infinito
			try:
				operation = input("\nInsira a operação desejada (get ou set): ") # Ler a operação desejada
				if operation not in ['get', 'set']: # Se a operação for inválida
					print("Operação inválida, tente novamente.") # Imprimir uma mensagem de erro
					continue # Voltar ao início do ciclo

				P = int(input("Insira o identificador do pedido (P): ")) # Ler o identificador do pedido

				if operation == 'get': # Se a operação for get
					NL = int(input("Insira o número de instâncias desejadas (NL): ")) # Ler o número de instâncias desejadas
					L = [] # Lista de instâncias desejadas
					for _ in range(NL): # Para cada instância desejada
						instance = input("Insira o identificador da instância: ") # Ler o identificador da instância
						N = int(input("Insira o valor de N: ")) # Ler o valor de N
						if N < 0: # Se o valor de N for inválido
							print("O valor de N tem de ser maior ou igual a 0.") # Imprimir uma mensagem de erro
							continue # Voltar ao início do ciclo
						L.append((instance, N)) # Adicionar a instância e o valor de N à lista de instâncias desejadas
					get_pdu = manager.snmpkeyshare_get(P, NL, L, ip, port) # Enviar o pedido get para o agente
					print("Resposta snmpkeyshare-get recebida:") # Imprimir a resposta
					print(get_pdu.__str__()) # Imprimir a resposta

				else:  # operation == 'set'
					NW = int(input("Insira o número de instâncias a serem modificadas (NW): ")) # Ler o número de instâncias a serem modificadas
					W = [] # Lista de instâncias a serem modificadas
					for _ in range(NW): # Para cada instância a ser modificada
						instance = input("Insira o identificador da instância: ") # Ler o identificador da instância
						if instance == "3.2.1.6.0": # Se a instância for a chave
							print("Selecione a visibilidade da chave:") # Ler a visibilidade da chave
							print("0 - Invisível") 
							print("1 - Visível para o pedido") 
							print("2 - Visível para todos") 
							visibility = int(input("Insira a visibilidade desejada: ")) 
							if visibility not in [0, 1, 2]: # Se a visibilidade for inválida
								print("Visibilidade inválida, tente novamente.") # Imprimir uma mensagem de erro
								continue # Voltar ao início do ciclo
							W.append((instance, visibility)) # Adicionar a instância e a visibilidade à lista de instâncias a serem modificadas
						else: # Se a instância não for a chave
							value = input("Insira o novo valor para a instância: ") # Ler o novo valor para a instância
							W.append((instance, value)) # Adicionar a instância e o novo valor à lista de instâncias a serem modificadas
					set_pdu = manager.snmpkeyshare_set(P, NW, W, ip, port) # Enviar o pedido set para o agente
					print("Resposta snmpkeyshare-set recebida:") # Imprimir a resposta
					print(set_pdu.__str__()) # Imprimir a resposta
			except ValueError as e: # Se o valor introduzido for inválido
				print(e) # Imprimir uma mensagem de erro
				continue # Voltar ao início do ciclo
	except KeyboardInterrupt: # Se o utilizador terminar o programa
		print("\nO gestor foi terminado pelo utilizador.") # Imprimir uma mensagem de erro


if __name__ == '__main__': # Se o programa for executado diretamente
	main() # Executar a função main
