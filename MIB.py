from datetime import datetime
from keyMaintenance import *
from SNMPKeySharePDU import *



class SNMPKeyShareMIB:

    def __init__(self):
        current_datetime = datetime.now()
        self.mib = {
            "1.3.6.1.2.1.1.1": current_datetime.strftime("%Y%m%d"),  # systemRestartDate
            "1.3.6.1.2.1.1.2": current_datetime.strftime("%H%M%S"),  # systemRestartTime
            "1.3.6.1.2.1.1.3": 1024,  # systemKeySize
            "1.3.6.1.2.1.1.4": 60,  # systemIntervalUpdate
            "1.3.6.1.2.1.1.5": 100,  # systemMaxNumberOfKeys
            "1.3.6.1.2.1.1.6": 3600,  # systemKeysTimeToLive
            "1.3.6.1.2.1.2.1": b"masterkey",  # configMasterKey
            "1.3.6.1.2.1.2.2": 65,  # configFirstCharOfKeysAlphabet
            "1.3.6.1.2.1.2.3": 26,  # configCardinalityOfKeysAlphabet
            "1.3.6.1.2.1.3.1": 0,  # dataNumberOfValidKeys
            "1.3.6.1.2.1.3.2": [],  # dataTableGeneratedKeys
        }

        self.read_only_oids = {"1.3.6.1.2.1.1.1", "1.3.6.1.2.1.1.2", "1.3.6.1.2.1.3.1"}

    def oid_tuple_to_string(oid_tuple):
        return '.'.join(map(str, oid_tuple))
    
    def get(self, oid):
        value = self.mib[oid]
        return value

    def set(self, oid, value):
        if oid in self.read_only_oids:
            raise ValueError(f"O OID {oid} é de leitura apenas.")
        self.mib[oid] = value

    def setAdmin(self, oid, value):
        self.mib[oid] = value

    def add_entry(self, entry):
        self.mib["1.3.6.1.2.1.3.2"].append(entry)

    def remove_entry(self, entry):
        self.mib["1.3.6.1.2.1.3.2"].remove(entry)

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

    def setAdmin(self, oid, value):
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