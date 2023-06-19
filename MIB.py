from datetime import datetime, timedelta


class InstanceData:

	""" Classe que representa os dados de uma instância da MIB """

	def __init__(self, access_type, instance_type, value):
		self.access_type = access_type # RO = Read Only, RW = Read Write
		self.instance_type = instance_type # Int = Integer, Str = String
		self.value = value # Valor da instância


class SNMPKeyShareMIB:

	""" Classe que representa a MIB SNMPKeyShare """

	def __init__(self):

		""" Construtor da classe """

		current_datetime = datetime.now() # Data e hora atuais

		self.mib = {
			"1.1.0": InstanceData("RO", "Int", int(current_datetime.strftime("%Y%m%d"))),  # systemRestartDate
			"1.2.0": InstanceData("RO", "Int", int(current_datetime.strftime("%H%M%S"))),  # systemRestartTime
			"1.3.0": InstanceData("RO", "Int", 10),  # systemKeySize
			"1.4.0": InstanceData("RW", "Int", 0),  # systemIntervalUpdate
			"1.5.0": InstanceData("RW", "Int", 0),  # systemMaxNumberOfKeys
			"1.6.0": InstanceData("RW", "Int", 3600),  # systemKeysTimeToLive
			"2.1.0": InstanceData("RW", "Str", "placeholder"),  # configMasterKey
			"2.2.0": InstanceData("RW", "Int", 33),  # configFirstCharOfKeysAlphabet
			"2.3.0": InstanceData("RW", "Int", 94),  # configCardinalityOfKeysAlphabet
			"3.1.0": InstanceData("RO", "Int", 0),  # dataNumberOfValidKeys
		}

	"""
	-- when a manager/client wants to request a generation of a key it 
	-- sends a set() request to write 0,1 or 2 into the keyVisibility.0 instance; 
	-- the agent will create a new key (Id=KI) and will answer with the value of the new keyVisibility.KI instance; 
	-- the manager/agent will then retrieve any required information from the agent, including the keyValue.KI value, using get() requests.
	"""

	# Pensar nisso como 3.2.1 é a tabela de dados e o próximo valor é o índice da coluna e o current_key_id é o índice da linha

	def add_entry_to_dataTableGeneratedKeys(self, current_key_id, key, KeyRequester, key_expiration_date, key_expiration_time, key_visibility=0):

		"""Adiciona uma entrada à tabela de dados"""

		self.mib[f"3.2.1.1.{current_key_id}"] = InstanceData("RO", "Int", current_key_id)  # keyId
		self.mib[f"3.2.1.2.{current_key_id}"] = InstanceData("RO", "Str", key)  # keyValue
		self.mib[f"3.2.1.3.{current_key_id}"] = InstanceData("RO", "Str", KeyRequester)  # KeyRequester
		self.mib[f"3.2.1.4.{current_key_id}"] = InstanceData("RO", "Int", key_expiration_date)  # keyExpirationDate
		self.mib[f"3.2.1.5.{current_key_id}"] = InstanceData("RO", "Int", key_expiration_time)  # keyExpirationTime
		self.mib[f"3.2.1.6.{current_key_id}"] = InstanceData("RO", "Int", key_visibility)  # keyVisibility (0 = invisible, 1 = visible to requester, 2 = visible to all)
		oid = f"3.2.1.6.{current_key_id}" # keyVisibility
		return oid, key_visibility # Retorna o OID e o valor da visibilidade da chave

	def get_id_from_oid(self, oid):

		"""Retorna o ID de uma chave a partir do OID"""

		return oid.split(".")[-1] # Retorna o último elemento do OID

	def remove_entry_from_dataTableGeneratedKeys(self, oid):

		"""Remove uma entrada da tabela de dados"""

		ident = self.get_id_from_oid(oid) # Identificador da entrada
		for i in range(1, 7): # Para cada coluna da entrada
			del self.mib[f"3.2.1.{i}.{ident}"] # Remover a entrada

	def get(self, oid):

		"""Retorna o valor de uma instância da MIB"""

		if oid not in self.mib: # Se o OID não existir
			raise ValueError(f"O OID {oid} não existe.") # Lançar uma exceção
		return self.mib[oid].value # Retornar o valor da instância

	def get_next(self, oid, current_key_id=None):

		"""Retorna o próximo OID e o seu valor"""

		if oid not in self.mib: # Se o OID não existir
			raise ValueError(f"O OID {oid} não existe.") # Lançar uma exceção

		keys = list(self.mib.keys()) # Lista de OIDs
		idx = keys.index(oid) # Índice do OID

		if idx == len(keys) - 1: # Se o OID for o último
			raise ValueError(f"O OID {oid} é o último OID na MIB.") # Lançar uma exceção

		if current_key_id is not None: # Se o ID da chave atual for especificado
			if current_key_id != self.get_id_from_oid(oid): # Se o ID da chave atual não for o mesmo que o ID da chave atual
				raise ValueError(f"O ID {current_key_id} não pertence ao OID {oid}.") # Lançar uma exceção

		next_oid = keys[idx + 1] # Próximo OID
		return next_oid, self.mib[next_oid].value # Retornar o próximo OID e o seu valor

	def set(self, oid, value):

		"""Define o valor de uma instância da MIB"""

		if oid not in self.mib: # Se o OID não existir
			raise ValueError(f"O OID {oid} não existe.") # Lançar uma exceção
		
		if self.mib[oid].access_type == "RO": # Se o OID for de leitura apenas
			raise ValueError(f"O OID {oid} é de leitura apenas.") # Lançar uma exceção
		
		target_type = self.mib[oid].instance_type.casefold() # Tipo de valor esperado

		if target_type != type(value).__name__.casefold(): # Se o tipo de valor não for o esperado

			# Tentativa de conversão do tipo de valor
			try:
				if target_type == "int".casefold(): # Se o tipo de valor for inteiro
					value = int(value) # Converter para inteiro
				elif target_type == "Str".casefold(): # Se o tipo de valor for string
					value = str(value) # Converter para string
			except ValueError: # Se não for possível converter o tipo de valor
				raise ValueError(f"Não foi possível converter o tipo de valor {type(value)} para {target_type}.") # Lançar uma exceção

		self.mib[oid].value = value # Definir o valor da instância

	def setAdmin(self, oid, value):

		"""Define o valor de uma instância da MIB sem verificar o acesso"""

		if oid not in self.mib: # Se o OID não existir
			raise ValueError(f"O OID {oid} não existe.") # Lançar uma exceção
		
		target_type = self.mib[oid].instance_type.casefold() # Tipo de valor esperado

		if target_type != type(value).__name__.casefold(): # Se o tipo de valor não for o esperado

			# Tentativa de conversão do tipo de valor
			try:
				if target_type == "int".casefold(): # Se o tipo de valor for inteiro
					value = int(value) # Converter para inteiro
				elif target_type == "Str".casefold(): # Se o tipo de valor for string
					value = str(value) # Converter para string
			except ValueError: # Se não for possível converter o tipo de valor
				raise ValueError(f"Não foi possível converter o tipo de valor {type(value)} para {target_type}.") # Lançar uma exceção

		self.mib[oid].value = value # Definir o valor da instância
