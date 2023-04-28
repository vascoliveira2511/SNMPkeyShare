import re
import socket
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

        fields = pdu_string.strip('\x00').split(';')
        S = int(fields[0])
        NS = int(fields[1])
        Q = fields[2].split(',') if fields[2] else []
        P = int(fields[3])
        Y = int(fields[4])
        NL_or_NW = int(fields[5])
        L_or_W = [tuple(map(int, re.findall(r'\d+', item)))
                  for item in fields[6].split('-')] if fields[6] else []
        NR = int(fields[7])
        R = [tuple(map(int, re.findall(r'\d+', item)))
             for item in fields[8].split('-')] if fields[8] else []

        return SNMPKeySharePDU(S, NS, Q, P, Y, NL_or_NW, L_or_W, NR, R)
