import random
from collections import deque

def random_with_seed(seed, min_val, max_val):
    random.seed(seed)
    return random.randint(min_val, max_val)

def print_matrix(matrix):
    for row in matrix:
        formatted_row = " ".join([f"{cell:3}" for cell in row])
        print(formatted_row)

def transpose(M):
    if isinstance(M[0], list):
        return [item for sublist in M for item in sublist]
    else:
        return [[M[i] for i in range(len(M))]]

# Função para rotacionar uma lista n posições para a direita
def rotate(s, n):
    d = deque(s)
    d.rotate(n)
    return list(d)

# Função para rotacionar uma coluna específica de uma matriz n posições para baixo
def rotate_vertical(matrix, col, n):
    column = [matrix[i][col] for i in range(len(matrix))]
    rotated_col = rotate(column, n)
    for i in range(len(matrix)):
        matrix[i][col] = rotated_col[i]

# Função para gerar as matrizes ZA, ZB, ZC e ZD (ou ZS) e a matriz Z
def generate_matrices(M, K, use_zs=True):
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
    ZC = [[random.randint(0, 255) for _ in range(K)] for _ in range(K)]

    """Criar uma matriz ZC de K x K bytes em que ZC[i,j] = random(ZA[i,j],0,255), em que a função
    random(seed,min,max)1 retorna um número aleatório entre min e max usando a semente seed;
    criar uma matriz ZD de K x K bytes em que ZD[i,j] = random(ZB[i,j],0,255); em alternativa pode
    ser criada apenas uma matriz ZS de K x K bytes em que ZS[i,j] = random(S,0,255);"""
    if use_zs:
        S = random.randint(0, 255)
        ZS = [[random_with_seed(S, 0, 255) for _ in range(K)] for _ in range(K)]
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
        
    return ZA, ZB, ZC, ZD if not use_zs else ZS, Z

# Exemplo de uso:

K = 10 # Tamanho da matriz
M_string = "07994506586870582927"
M = list(map(int, M_string))
use_zs = False

if use_zs:
    ZA, ZB, ZS, Z = generate_matrices(M, K, use_zs)
    print("Matriz ZA:")
    print_matrix(ZA)
    print("\nMatriz ZB:")
    print_matrix(ZB)
    print("\nMatriz ZS:")
    print_matrix(ZS)
    print("\nMatriz Z:")
    print_matrix(Z)
else:
    ZA, ZB, ZC, ZD, Z = generate_matrices(M, K, use_zs)
    print("Matriz ZA:")
    print_matrix(ZA)
    print("\nMatriz ZB:")
    print_matrix(ZB)
    print("\nMatriz ZC:")
    print_matrix(ZC)
    print("\nMatriz ZD:")
    print_matrix(ZD)
    print("\nMatriz Z:")
    print_matrix(Z)