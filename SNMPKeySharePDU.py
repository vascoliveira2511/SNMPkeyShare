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
            result = []
            result.append(f"Identificação do modelo de segurança (S): {self.S}")
            result.append(f"Número de parâmetros necessários à implementação dos mecanismos de segurança (NS): {self.NS}")
            result.append(f"Lista dos parâmetros necessários à implementação dos mecanismos de segurança (Q): {self.Q}")
            result.append(f"Identificação do pedido (P): {self.P}")
            result.append(f"Identificação do tipo de primitiva (Y): {self.Y}")

            # Aqui assumimos que L_or_W e R são listas de tuplas
            result.append(f"Número de elementos da lista de instâncias e valores associados (NL ou NW): {self.NL_or_NW}")
            for index, (I_ID, H_or_N) in enumerate(self.L_or_W, start=1):
                result.append(f"Instância {index}: I-ID={I_ID}, H_or_N={H_or_N}")

            result.append(f"Número de elementos da lista de erros (NR): {self.NR}")
            for index, (I_ID, E) in enumerate(self.R, start=1):
                result.append(f"Erro {index}: I-ID={I_ID}, E={E}")

            return "\n".join(result)


    @classmethod
    def from_string(cls, data):
        lines = data.split("\n")
        print(f"DEBUG: {lines[0]}")  # Depuração: imprime a linha antes de tentar dividi-la
        S = int(lines[0].split(": ")[1])
        NS = int(lines[1].split(": ")[1])
        Q = [int(q) for q in lines[2].split(": ")[1].strip("[]").split(", ")]
        P = int(lines[3].split(": ")[1])
        Y = int(lines[4].split(": ")[1])
        NL_or_NW = int(lines[5].split(": ")[1])

        # Processar a lista L_or_W
        L_or_W_start = 6
        L_or_W_end = L_or_W_start + NL_or_NW
        L_or_W = []
        for line in lines[L_or_W_start:L_or_W_end]:
            parts = line.split(": ")
            I_ID = parts[1].split(", ")[0].split("=")[1]
            H_or_N = parts[1].split(", ")[1].split("=")[1]
            L_or_W.append((I_ID, H_or_N))

        NR = int(lines[L_or_W_end].split(": ")[1])

        # Processar a lista R
        R_start = L_or_W_end + 1
        R = []
        for line in lines[R_start:]:
            parts = line.split(": ")
            I_ID = parts[1].split(", ")[0].split("=")[1]
            E = parts[1].split(", ")[1].split("=")[1]
            R.append((I_ID, E))

        return cls(S=S, NS=NS, Q=Q, P=P, Y=Y, NL_or_NW=NL_or_NW, L_or_W=L_or_W, NR=NR, R=R)

