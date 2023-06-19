import pickle


class SNMPKeySharePDU:
	
	"""Classe que representa um PDU SNMPKeyShare"""

	def __init__(self, S=0, NS=0, Q=None, P=0, Y=0, NL_or_NW=0, L_or_W=None, NR=0, R=None):

		"""Construtor da classe"""

		if R is None: # Se a lista de erros for None
			R = [] # Inicializar a lista de erros
		if L_or_W is None: # Se a lista de instâncias for None
			L_or_W = [] # Inicializar a lista de instâncias
		if Q is None: # Se a lista de parâmetros for None
			Q = [] # Inicializar a lista de parâmetros

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

		return pickle.dumps(self) # Serializar o PDU

	@staticmethod
	def deserialize(data):

		"""Deserializar uma string para um PDU usando pickle"""

		return pickle.loads(data) # Deserializar o PDU

	def __str__(self):

		"""Representação em string do PDU"""

		return f"""
		S  (Modelo de segurança):         {self.S}
		NS (Número de parâmetros SM):     {self.NS}
		Q  (Lista de parâmetros SM):      {self.Q}
		
		P  (Id do pedido):                {self.P}
		Y  (Tipo de Primitiva):           {self.Y} ({
			"Response" if self.Y == 0 else
			"Get" if self.Y == 1 else
			"Set" if self.Y == 2 else
			"Unknown"
		})
		
		NL/NW (Número de instâncias):     {self.NL_or_NW}
		L/W   (Lista de instâncias):      {self.L_or_W}
		
		NR    (Número de erros):     	  {self.NR}
		R     (Lista de erros):           {self.R}
		"""
