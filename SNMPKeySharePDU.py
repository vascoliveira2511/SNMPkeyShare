import pickle


class SNMPKeySharePDU:
	
	"""Classe que representa um PDU SNMPKeyShare"""

	def __init__(self, S=0, NS=0, Q=[], P=0, Y=0, NL_or_NW=0, L_or_W=[], NR=0, R=[]):

		"""Construtor da classe"""

		self.S = S  # Identificação do modelo de segurança
		self.NS = NS  # Número de parâmetros necessários à implementação dos mecanismos de segurança
		self.Q = Q  # Lista dos parâmetros necessários à implementação dos mecanismos de segurança
		self.P = P  # Identificação do pedido
		# Identificação do tipo de primitiva (0 = response, 1 = get, 2 = set)
		self.Y = Y
		# Número de elementos da lista de instâncias e valores associados (NL ou NW)
		self.NL_or_NW = NL_or_NW
		# Lista de instâncias e valores associados (L ou W)
		self.L_or_W = L_or_W
		self.NR = NR  # Número de elementos da lista de erros
		self.R = R  # Lista de erros e valores associados

	def serialize(self):

		"""Serializar o PDU para uma string usando pickle"""

		return pickle.dumps(self)

	@staticmethod
	def deserialize(data):

		"""Deserializar uma string para um PDU usando pickle"""

		return pickle.loads(data)

	def __str__(self):

		"""Representação em string do PDU"""

		return f"""
		S  (Security Model):          {self.S}
		NS (Number of SM parameters): {self.NS}
		Q  (SM Parameter list):       {self.Q}
		
		P  (Request ID):              {self.P}
		Y  (Primitive Type):          {self.Y} ({
			"Response" if self.Y == 0 else
			"Get" if self.Y == 1 else
			"Set" if self.Y == 2 else
			"Unknown"
		})
		
		NL/NW (Number of elements):   {self.NL_or_NW}
		L/W   (Instance list):        {self.L_or_W}
		
		NR    (Number of errors):     {self.NR}
		R     (Error list):           {self.R}
		"""
