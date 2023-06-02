from keyMaintenance import *
from SNMPKeySharePDU import *


class SNMPKeyShareMIB:
    def __init__(self):
        self.mib = {
            "1.3.6.1.2.1.1.1": 0,  # systemRestartDate
            "1.3.6.1.2.1.1.2": 0,  # systemRestartTime
            "1.3.6.1.2.1.1.3": 0,  # systemKeySize
            "1.3.6.1.2.1.1.4": 0,  # systemIntervalUpdate
            "1.3.6.1.2.1.1.5": 0,  # systemMaxNumberOfKeys
            "1.3.6.1.2.1.1.6": 0,  # systemKeysTimeToLive
            "1.3.6.1.2.1.2.1": b"",  # configMasterKey
            "1.3.6.1.2.1.2.2": 33,  # configFirstCharOfKeysAlphabet
            "1.3.6.1.2.1.2.3": 94,  # configCardinalityOfKeysAlphabet
            "1.3.6.1.2.1.3.1": 0,  # dataNumberOfValidKeys
            "1.3.6.1.2.1.3.2": [],  # dataTableGeneratedKeys
        }

        self.read_only_oids = {"1.3.6.1.2.1.1.1", "1.3.6.1.2.1.1.2", "1.3.6.1.2.1.3.1"}

    def get(self, oid):
        return self.mib.get(oid)

    def set(self, oid, value):
        if oid in self.read_only_oids:
            raise ValueError(f"O OID {oid} é de leitura apenas.")
        self.mib[oid] = value

    def add_entry(self, entry):
        self.mib["1.3.6.1.2.1.3.2"].append(entry)

class DataTableGeneratedKeysEntry:
    def __init__(self, keyId):
        self.entry = {
            "1.3.6.1.2.1.3.2.1.1": keyId,  # keyId
            "1.3.6.1.2.1.3.2.1.2": b"",  # keyValue
            "1.3.6.1.2.1.3.2.1.3": b"",  # KeyRequester
            "1.3.6.1.2.1.3.2.1.4": 0,  # keyExpirationDate
            "1.3.6.1.2.1.3.2.1.5": 0,  # keyExpirationTime
            "1.3.6.1.2.1.3.2.1.6": 0,  # keyVisibility
        }

        self.read_only_oids = {"1.3.6.1.2.1.3.2.1.1", "1.3.6.1.2.1.3.2.1.2", "1.3.6.1.2.1.3.2.1.3", "1.3.6.1.2.1.3.2.1.4", "1.3.6.1.2.1.3.2.1.5"}

    def get(self, oid):
        return self.entry.get(oid)

    def set(self, oid, value):
        if oid in self.read_only_oids:
            raise ValueError(f"O OID {oid} é de leitura apenas.")
        self.entry[oid] = value


# Exemplo de utilização da MIB

"""	
mib = SNMPKeyShareMIB()

entry = DataTableGeneratedKeysEntry(1)
entry.set("1.3.6.1.2.1.3.2.1.2", b"key1")
entry.set("1.3.6.1.2.1.3.2.1.3", b"requester1")
entry.set("1.3.6.1.2.1.3.2.1.4", 20230602)
entry.set("1.3.6.1.2.1.3.2.1.5", 101010)
entry.set("1.3.6.1.2.1.3.2.1.6", 2)

mib.add_entry(entry)

print(mib.get("1.3.6.1.2.1.3.2")[0].get("1.3.6.1.2.1.3.2.1.1"))  # Imprime: 1
"""	