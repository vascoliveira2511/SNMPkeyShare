import pickle
import socket
import time
from SNMPKeySharePDU import SNMPKeySharePDU


class SNMPKeyShareManager:

	"""Classe que representa um gestor SNMPKeyShare"""

	def __init__(self, timeout):

		"""Construtor da classe"""

		self.timeout = timeout
		self.requests = {}
		self.last_request_time = {}

	def snmpkeyshare_get(self, P, NL, L, agent_ip, agent_port):

		"""Envia um pedido snmpkeyshare-get para o agente SNMPKeyShare"""	

		if P in self.last_request_time and (time.time() - self.last_request_time[P]) < self.timeout:
			raise ValueError(
				f"Não é permitido enviar outro pedido com o mesmo P ({P}) durante {self.timeout} segundos.")

		self.last_request_time[P] = time.time()

		pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=1, NL_or_NW=NL, L_or_W=L, NR=0, R=[])

		# Enviar o PDU para o agente utilizando comunicação UDP
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:

			udp_socket.settimeout(self.timeout)

			pdu = pickle.dumps(pdu)
			udp_socket.sendto(pdu, (agent_ip, agent_port))

			try:
				response_data, _ = udp_socket.recvfrom(1024)

				response_pdu = pickle.loads(response_data)

				return response_pdu

			except socket.timeout:
				print(
					f"O agente não respondeu no intervalo de tempo {self.timeout} segundos.")
				return None

	def snmpkeyshare_set(self, P, NW, W, agent_ip, agent_port):

		"""Envia um pedido snmpkeyshare-set para o agente SNMPKeyShare"""

		if P in self.last_request_time and (time.time() - self.last_request_time[P]) < self.timeout:
			raise ValueError(
				f"Não é permitido enviar outro pedido com o mesmo P ({P}) durante {self.timeout} segundos.")

		self.last_request_time[P] = time.time()
		pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=2, NL_or_NW=NW, L_or_W=W, NR=0, R=[])

		# Enviar o PDU para o agente usando comunicação UDP
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
			udp_socket.settimeout(self.timeout)

			pdu = pickle.dumps(pdu)
			udp_socket.sendto(pdu, (agent_ip, agent_port))

			try:
				response_data, _ = udp_socket.recvfrom(1024)

				response_pdu = pickle.loads(response_data)

				return response_pdu

			except socket.timeout:
				print(
					f"O agente não respondeu no intervalo de tempo {self.timeout} segundos.")
				return None


def main():

	"""Função principal"""

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
				instance = input("Insira o identificador da instância: ")
				N = int(input("Insira o valor de N: "))
				if N < 0:
					print("O valor de N tem de ser maior ou igual a 0.")
					continue
				L.append((instance, N))
			get_pdu = manager.snmpkeyshare_get(P, NL, L, ip, port)
			print("Resposta snmpkeyshare-get recebida:")
			print(get_pdu.__str__())

		else:  # operation == 'set'
			NW = int(input("Insira o número de instâncias a serem modificadas (NW): "))
			W = []
			for _ in range(NW):
				instance = input("Insira o identificador da instância: ")
				if instance == "3.2.1.6.0":
					print("Selecione a visibilidade da chave:")
					print("0 - Invisível")
					print("1 - Visível para o pedido")
					print("2 - Visível para todos")
					visibility = int(input("Insira a visibilidade desejada: "))
					if visibility not in [0, 1, 2]:
						print("Visibilidade inválida, tente novamente.")
						continue
					W.append((instance, visibility))
				else:
					value = input("Insira o novo valor para a instância: ")
					W.append((instance, value))
			set_pdu = manager.snmpkeyshare_set(P, NW, W, ip, port)
			print("Resposta snmpkeyshare-set recebida:")
			print(set_pdu.__str__())


if __name__ == '__main__':
	main()