import time


class SNMPKeySharePDU:
    def __init__(self, S=0, NS=0, Q=[], P=0, Y=0, NL_or_NW=0, L_or_W=[], NR=0, R=[]):
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

    def __str__(self):
        return f"{self.S};{self.NS};{','.join(map(str, self.Q))};{self.P};{self.Y};{self.NL_or_NW};{','.join(map(str, self.L_or_W))};{self.NR};{','.join(map(str, self.R))}"

    @staticmethod
    def from_string(pdu_string):
        fields = pdu_string.split(';')
        S = int(fields[0])
        NS = int(fields[1])
        Q = list(map(int, fields[2].split(','))) if fields[2] else []
        P = int(fields[3])
        Y = int(fields[4])
        NL_or_NW = int(fields[5])
        L_or_W = list(map(int, fields[6].split(','))) if fields[6] else []
        NR = int(fields[7])
        R = list(map(int, fields[8].split(','))) if fields[8] else []
        return SNMPKeySharePDU(S, NS, Q, P, Y, NL_or_NW, L_or_W, NR, R)


class SNMPKeyShareManager:

    def __init__(self, timeout):

        self.timeout = timeout
        self.requests = {}
        self.last_request_time = {}

    def snmpkeyshare_get(self, P, NL, L):

        if P in self.last_request_time and (time.time() - self.last_request_time[P]) < self.timeout:
            raise ValueError(
                f"Não é permitido enviar outro pedido com o mesmo P ({P}) durante {self.timeout} segundos.")

        self.last_request_time[P] = time.time()
        pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=1,
                              NL_or_NW=NL, L_or_W=L, NR=0, R=[])

        # Aqui você deve enviar o PDU para o agente e esperar pela resposta.
        # Como isso depende do método de comunicação utilizado, não é incluído neste exemplo.

        return pdu

    def snmpkeyshare_set(self, P, NW, W):

        if P in self.last_request_time and (time.time() - self.last_request_time[P]) < self.timeout:
            raise ValueError(
                f"Não é permitido enviar outro pedido com o mesmo P ({P}) durante {self.timeout} segundos.")

        self.last_request_time[P] = time.time()
        pdu = SNMPKeySharePDU(S=0, NS=0, Q=[], P=P, Y=2,
                              NL_or_NW=NW, L_or_W=W, NR=0, R=[])

        # Aqui você deve enviar o PDU para o agente e esperar pela resposta.
        # Como isso depende do método de comunicação utilizado, não é incluído neste exemplo.

        return pdu
