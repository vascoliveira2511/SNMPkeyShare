import random
from collections import deque
import time


def random_with_seed(seed, min_val, max_val):

	"""Função que retorna um número aleatório entre min_val e max_val usando a semente seed"""

	random.seed(seed)
	return random.randint(min_val, max_val)


def print_matrix(matrix):

	"""Função para imprimir uma matriz de forma formatada"""

	for row in matrix:
		formatted_row = " ".join([f"{cell:3}" for cell in row])
		print(formatted_row)


def transpose(M):

	"""Função para transpor uma matriz"""

	if isinstance(M[0], list):
		return [item for sublist in M for item in sublist]
	else:
		return [[M[i] for i in range(len(M))]]


def rotate(s, n):

	"""Função para rodar uma sequência n posições para a direita"""

	d = deque(s)
	d.rotate(n)
	return list(d)



def rotate_vertical(matrix, col, n):

	"""Função para rodar uma coluna n posições para baixo"""

	column = [matrix[i][col] for i in range(len(matrix))]
	rotated_col = rotate(column, n)
	for i in range(len(matrix)):
		matrix[i][col] = rotated_col[i]


def generate_matrices(M, K, use_zs=True):

	"""Função para gerar as matrizes ZA, ZB, ZC, ZD e Z"""


	"""Seja M1 uma sequência com os primeiros K bytes de M e M2 outra sequência com os K bytes
	restantes de M (ou seja, M = M1+M2);"""
	M1 = M[:K]
	M2 = M[K:]

	"""Criar uma matriz ZA de K x K bytes em que a primeira linha é igual a M1 e as restantes linhas
	são iguais a rotate(M1,i), em que i é o índice da linha e a função rotate(M,n) retorna uma
	sequência com o mesmo comprimento de M mas com os seus elementos rodados pela direita n
	vezes; por exemplo, rotate(“012345”,1) = “501234”;"""
	ZA = [rotate(M1, i) for i in range(K)]

	"""Criar uma matriz ZB de K x K bytes em que a primeira coluna é igual a transpose(M2) e as
	restantes colunas são iguais a transpose(rotate(M2,j)), em que j é o índice da coluna e a função
	transpose(M) retorna uma sequência com o mesmo comprimento de M mas com os seus
	elementos alinhados/organizados verticalmente, de cima para baixo, numa coluna, se M for uma
	sequência com os elementos alinhados/organizados horizontalmente; se M já for uma sequência
	com os elementos alinhados/organizados verticalmente a função retorna uma sequência com o
	mesmo comprimento de M mas com os seus elementos alinhados/organizados horizontalmente,
	da esquerda para a direita, numa linha"""
	ZB = [transpose(rotate(M2, j))[0] for j in range(K)]
	ZB = list(map(list, zip(*ZB)))

	"""Criar uma matriz ZC de K x K bytes em que ZC[i,j] = random(ZA[i,j],0,255), em que a função
	random(seed,min,max)1 retorna um número aleatório entre min e max usando a semente seed;
	criar uma matriz ZD de K x K bytes em que ZD[i,j] = random(ZB[i,j],0,255); em alternativa pode
	ser criada apenas uma matriz ZS de K x K bytes em que ZS[i,j] = random(S,0,255);"""
	if use_zs:
		ZS = [[random_with_seed(random.randint(0, 255), 0, 255) for _ in range(K)] for _ in range(K)]
	else:
		ZC = [[random_with_seed(ZA[i][j], 0, 255) for j in range(K)] for i in range(K)]
		ZD = [[random_with_seed(ZB[i][j], 0, 255) for j in range(K)] for i in range(K)]

	"""Calcular uma matriz Z de K x K bytes em que Z[i,j] = xor(ZA[i,j],ZB[i,j],ZC[i,j],ZD[i,j]) ou, em
	alternativa, Z[i,j] = xor(ZA[i,j],ZB[i,j],ZS[i,j]), e em que xor(A,B,C,…) devolve um byte que é o
	resultado de aplicar a função booleana xor (Exclusive OR) aos seus argumentos (bytes) duma
	forma binária (bit a bit); a função xor pode ser substituída por uma outra função fm(a,b) que
	devolve um valor a partir de dois argumentos de tal forma que o valor devolvido e os argumentos
	têm valores possíveis no mesmo limite e todos os valores possivelmente devolvidos são
	uniformemente distribuídos; a implementação desta de fm pode apresentar vantagens na
	implementação em relação à função xor se for implementada à custa dum simples acesso a um
	array predefinido e quando os valores possíveis dos argumentos são limitados (neste caso, a
	função fm pode ser implementada como o acesso direto a um elemento dum array predefinido no
	ficheiro F)."""
	if use_zs:
		Z = [[ZS[i][j] ^ ZA[i][j] ^ ZB[i][j] for j in range(K)] for i in range(K)]
	else:
		Z = [[ZC[i][j] ^ ZD[i][j] ^ ZA[i][j] ^ ZB[i][j] for j in range(K)] for i in range(K)]
	return Z


def process_Z(Z):

	"""Função para processar a matriz Z"""

	K = len(Z)
	for i in range(K):
		# 1. Atualizar a matriz Z de acordo com Zi* = rotate(Zi*,random(Z[i,0],0,K-1));
		Z[i] = rotate(Z[i], random_with_seed(Z[i][0], 0, K - 1))

	for j in range(K):
		# 2. Atualizar a matriz Z de acordo com Z*j = rotate_vertical(Z*j,random(Z[0,j],0,K-1))
		rotate_vertical(Z, j, random_with_seed(Z[0][j], 0, K - 1))


def generate_key(Z, N):

	"""Função para gerar uma chave"""

	K = len(Z)

	# 2. Escolhe-se uma linha Zi* de Z, de tal forma que i = random(N+Z[0,0],0,K-1);
	i = random_with_seed(N + Z[0][0], 0, K - 1)
	Zi_star = Z[i]

	# 3. Escolhe-se uma coluna Z*j de Z, de tal forma que j = random(Z[i,0],0,K-1);
	j = random_with_seed(Z[i][0], 0, K - 1)
	Zj_star = [Z[row][j] for row in range(K)]

	# 4. Calcula-se a chave através da expressão C = xor(Zi*,transpose(Z*j));
	C = [Zi_star[k] ^ Zj_star[k] for k in range(K)]

	# Converter os valores em caracteres ASCII legíveis
	C_ascii = "".join(chr(c % 75 + 48) for c in C)

	return C_ascii


def generate_random_K(min_val=5, max_val=15):

	"""Função para gerar um valor aleatório para K"""

	return random.randint(min_val, max_val)


def generate_random_M_string(K, min_val=0, max_val=9):

	"""Função para gerar uma string aleatória para M"""

	return "".join([str(random.randint(min_val, max_val)) for _ in range(2 * K)])
