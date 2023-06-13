from datetime import datetime


class SNMPKeyShareMIB:

	""""Classe que representa a MIB SNMPKeyShareMIB"""

	def __init__(self):

		"""Construtor da classe"""	
	
		current_datetime = datetime.now()

		self.mib = {
			"1.3.6.1.2.1.1.1.0": current_datetime.strftime("%Y%m%d"),  # systemRestartDate
			"1.3.6.1.2.1.1.2.0": current_datetime.strftime("%H%M%S"),  # systemRestartTime
			"1.3.6.1.2.1.1.3.0": 1024,  # systemKeySize
			"1.3.6.1.2.1.1.4.0": 60,  # systemIntervalUpdate
			"1.3.6.1.2.1.1.5.0": 100,  # systemMaxNumberOfKeys
			"1.3.6.1.2.1.1.6.0": 3600,  # systemKeysTimeToLive
			"1.3.6.1.2.1.2.1.0": b"masterkey",  # configMasterKey
			"1.3.6.1.2.1.2.2.0": 65,  # configFirstCharOfKeysAlphabet
			"1.3.6.1.2.1.2.3.0": 26,  # configCardinalityOfKeysAlphabet
			"1.3.6.1.2.1.3.1.0": 0,  # dataNumberOfValidKeys
			"1.3.6.1.2.1.3.2.1": [],  # dataTableGeneratedKeys
		}

		self.read_only_oids = [
			"1.3.6.1.2.1.1.1.0",
			"1.3.6.1.2.1.1.2.0",
			"1.3.6.1.2.1.3.1.0"
		]

	@staticmethod
	def oid_tuple_to_string(oid_tuple):

		"""Converte uma tupla de inteiros para uma string"""

		return '.'.join(map(str, oid_tuple))

	def get(self, oid):

		"""Retorna o valor de um OID"""	

		if oid not in self.mib:
			raise ValueError(f"O OID {oid} não existe.")
		value = self.mib[oid]
		return value

	def set(self, oid, value):

		"""Define o valor de um OID"""

		if oid not in self.mib:
			raise ValueError(f"O OID {oid} não existe.")
		if oid in self.read_only_oids:
			raise ValueError(f"O OID {oid} é de leitura apenas.")
		self.mib[oid] = value

	def set_admin(self, oid, value):

		"""Define o valor de um OID"""

		self.mib[oid] = value

	def add_entry(self, entry):

		"""Adiciona uma entrada à tabela de chaves geradas"""

		self.mib["1.3.6.1.2.1.3.2.1"].append(entry)

	def remove_entry(self, entry):
		"""Remove uma entrada da tabela de chaves geradas"""

		self.mib["1.3.6.1.2.1.3.2.1"].remove(entry)


class DataTableGeneratedKeysEntry:
	"""Classe que representa uma entrada da tabela de chaves geradas"""	

	def __init__(self, key_id):
		"""Construtor da classe"""
		self.entry = {
			"1.3.6.1.2.1.3.2.1.1.0": key_id,  # keyId
			"1.3.6.1.2.1.3.2.1.2.0": b"",  # keyValue
			"1.3.6.1.2.1.3.2.1.3.0": b"",  # KeyRequester
			"1.3.6.1.2.1.3.2.1.4.0": 0,  # keyExpirationDate
			"1.3.6.1.2.1.3.2.1.5.0": 0,  # keyExpirationTime
			"1.3.6.1.2.1.3.2.1.6.0": 0,  # keyVisibility
		}

		self.read_only_oids = [
			"1.3.6.1.2.1.3.2.1.1.0",
			"1.3.6.1.2.1.3.2.1.2.0",
			"1.3.6.1.2.1.3.2.1.3.0",
			"1.3.6.1.2.1.3.2.1.4.0",
			"1.3.6.1.2.1.3.2.1.5.0"
		]

	def get(self, oid):
		"""Retorna o valor de um OID"""
		if oid not in self.entry:
			raise ValueError(f"O OID {oid} não existe.")
		return self.entry.get(oid)

	def set(self, oid, value):
		"""Define o valor de um OID"""
		if oid not in self.entry:
			raise ValueError(f"O OID {oid} não existe.")
		if oid in self.read_only_oids:
			raise ValueError(f"O OID {oid} é de leitura apenas.")
		self.entry[oid] = value

	def set_admin(self, oid, value):
		"""Define o valor de um OID"""
		self.entry[oid] = value
