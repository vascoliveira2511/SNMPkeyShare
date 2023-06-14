from datetime import datetime


class InstanceData:
    def __init__(self, access_type, instance_type, value):
        self.access_type = access_type
        self.instance_type = instance_type
        self.value = value


class SNMPKeyShareMIB:
    def __init__(self):
        current_datetime = datetime.now()

        self.mib = {
            "1.1.0": InstanceData("RO", "String", current_datetime.strftime("%Y%m%d")),  # systemRestartDate
            "1.2.0": InstanceData("RO", "String", current_datetime.strftime("%H%M%S")),  # systemRestartTime
            "1.3.0": InstanceData("RO", "Int", 1024),  # systemKeySize
            "1.4.0": InstanceData("RW", "Int", 60),  # systemIntervalUpdate
            "1.5.0": InstanceData("RW", "Int", 100),  # systemMaxNumberOfKeys
            "1.6.0": InstanceData("RW", "Int", 3600),  # systemKeysTimeToLive
            "2.1.0": InstanceData("RW", "String", "masterkey"),  # configMasterKey
            "2.2.0": InstanceData("RW", "Int", 65),  # configFirstCharOfKeysAlphabet
            "2.3.0": InstanceData("RW", "Int", 26),  # configCardinalityOfKeysAlphabet
            "3.1.0": InstanceData("RO", "Int", 0),  # dataNumberOfValidKeys
        }

    def add_entry_to_dataTableGeneratedKeys(self, key_id):
        self.mib[f"3.2.1.1.{key_id}"] = InstanceData("RO", "Int", key_id)  # keyId
        self.mib[f"3.2.1.2.{key_id}"] = InstanceData("RO", "String", "")  # keyValue
        self.mib[f"3.2.1.3.{key_id}"] = InstanceData("RO", "String", "")  # KeyRequester
        self.mib[f"3.2.1.4.{key_id}"] = InstanceData("RO", "Int", 0)  # keyExpirationDate
        self.mib[f"3.2.1.5.{key_id}"] = InstanceData("RO", "Int", 0)  # keyExpirationTime
        self.mib[f"3.2.1.6.{key_id}"] = InstanceData("RO", "Int", 0)  # keyVisibility

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
		
