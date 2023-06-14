from datetime import datetime


class InstanceData:
    def __init__(self, access_type, instance_type, value):
        self.access_type = access_type
        self.instance_type = instance_type
        self.value = value


class SNMPKeyShareMIB:
    def __init__(self):
        current_datetime = datetime.now()
        self.current_key_id = 0

        self.mib = {
            "1.1.0": InstanceData("RO", "String", current_datetime.strftime("%Y%m%d")),  # systemRestartDate
            "1.2.0": InstanceData("RO", "String", current_datetime.strftime("%H%M%S")),  # systemRestartTime
            "1.3.0": InstanceData("RO", "Int", 1024),  # systemKeySize
            "1.4.0": InstanceData("RW", "Int", 60),  # systemIntervalUpdate
            "1.5.0": InstanceData("RW", "Int", 100),  # systemMaxNumberOfKeys
            "1.6.0": InstanceData("RW", "Int", 3600),  # systemKeysTimeToLive
            "2.1.0": InstanceData("RW", "String", "masterkey"),  # configMasterKey
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

    def add_entry_to_dataTableGeneratedKeys(self, key_visibility=0):
        self.mib[f"3.2.1.1.{self.current_key_id}"] = InstanceData("RO", "Int", self.current_key_id)  # keyId
        self.mib[f"3.2.1.2.{self.current_key_id}"] = InstanceData("RO", "String", "")  # keyValue
        self.mib[f"3.2.1.3.{self.current_key_id}"] = InstanceData("RO", "String", "")  # KeyRequester
        self.mib[f"3.2.1.4.{self.current_key_id}"] = InstanceData("RO", "Int", 0)  # keyExpirationDate
        self.mib[f"3.2.1.5.{self.current_key_id}"] = InstanceData("RO", "Int", 0)  # keyExpirationTime'
        self.mib[f"3.2.1.6.{self.current_key_id}"] = InstanceData("RO", "Int", key_visibility)  # keyVisibility (0 = invisible, 1 = visible to requester, 2 = visible to all)
        self.current_key_id += 1
        return f"3.2.1.6.{self.current_key_id}", key_visibility

    def get(self, oid):
        if oid not in self.mib:
            raise ValueError(f"O OID {oid} não existe.")
        return self.mib[oid].value

    def get_next(self, oid):
        if oid not in self.mib:
            raise ValueError(f"O OID {oid} não existe.")

        keys = list(self.mib.keys())
        idx = keys.index(oid)

        if idx == len(keys) - 1:
            raise ValueError(f"O OID {oid} é o último OID na MIB.")

        next_oid = keys[idx + 1]
        return next_oid, self.mib[next_oid].value

    def set(self, oid, value):
        if oid not in self.mib:
            raise ValueError(f"O OID {oid} não existe.")
        if self.mib[oid].access_type == "RO":
            raise ValueError(f"O OID {oid} é de leitura apenas.")
        if self.mib[oid].instance_type != type(value).__name__:
            raise ValueError(f"O OID {oid} é do tipo {self.mib[oid].instance_type}.")
        self.mib[oid].value = value
		
