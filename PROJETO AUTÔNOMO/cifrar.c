#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Função para rotacionar bits à esquerda ou direita, dependendo do valor de shift (é um mod 32)
static uint32_t rotl32(uint32_t value, unsigned int shift)
{
    return (value << shift) | (value >> (32 - shift)); 
}

// Função para imprimir dados em formato hexadecimal
static void print_hex(const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Função para realizar a operação de "quarter round" do ChaCha20
void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a = *a + *b; // soma dois numeros de 32 bits, se ultrapassar de 32 bits, o excedente é descartado
    *d = *d ^ *a; // Aplica XOR entre d e a
    *d = rotl32(*d, 16); // Rotaciona d 16 bits à esquerda

    *c = *c + *d;
    *b = *b ^ *c;
    *b = rotl32(*b, 12);

    *a = *a + *b;
    *d = *d ^ *a;
    *d = rotl32(*d, 8);

    *c = *c + *d;
    *b = *b ^ *c;
    *b = rotl32(*b, 7);
}

// Converte 4 bytes em um numero de 32 bits
uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

// Funcao principal do ChaCha20
void chacha20(uint8_t *dados, size_t tamanho,
              const uint8_t chave[32], const uint8_t nonce[12])
{
    // São as 4 constantes iniciais do ChaCha20, representando a string "expand 32-byte k"
    uint32_t estado[16] = {
        0x61707865, 0x3320646e,
        0x79622d32, 0x6b206574
    };

    // Adiciona a chave ao estado
    // A chave é dividida em 8 palavras de 32 bits
    for (int i = 0; i < 8; i++)
        estado[4 + i] = load32(chave + i * 4); 

    estado[12] = 1; // Contador

    // Adiciona o nonce
    for (int i = 0; i < 3; i++)
        estado[13 + i] = load32(nonce + i * 4);

    // Processa a mensagem em blocos de 64 bytes
    for (size_t pos = 0; pos < tamanho; pos += 64)
    {
        // Cria uma copia do estado para ser modificado
        uint32_t x[16];

        // Copia o estado original para x
        for (int i = 0; i < 16; i++)
            x[i] = estado[i];

        // 20 rodadas do ChaCha20
        for (int i = 0; i < 10; i++)
        {
            // opera nas colunas                              Matriz 4x4 do estado:
            quarter_round(&x[0], &x[4], &x[8], &x[12]);   //   [ 0  1  2  3 ]
            quarter_round(&x[1], &x[5], &x[9], &x[13]);   //   [ 4  5  6  7 ]
            quarter_round(&x[2], &x[6], &x[10], &x[14]);  //   [ 8  9 10 11 ]
            quarter_round(&x[3], &x[7], &x[11], &x[15]);  //   [ 12 13 14 15]

            // opera nas diagonais
            quarter_round(&x[0], &x[5], &x[10], &x[15]);
            quarter_round(&x[1], &x[6], &x[11], &x[12]);
            quarter_round(&x[2], &x[7], &x[8], &x[13]);
            quarter_round(&x[3], &x[4], &x[9], &x[14]);
        }

        // Soma o estado original e aplica XOR
        for (int i = 0; i < 16; i++)
        {
            uint32_t resultado = x[i] + estado[i]; // Adiciona o estado original ao resultado

            for (int j = 0; j < 4; j++)
            {
                size_t indice = pos + i * 4 + j;

                if (indice < tamanho)
                    dados[indice] ^= (uint8_t)(resultado >> (j * 8)); // Aplica XOR com os bytes do resultado
            }
        }

        estado[12]++; // Incrementa o contador para o próximo bloco
    }
}

int main()
{
    char mensagem[256];
    uint8_t chave[32];
    uint8_t nonce[12];

    // Chave fixa para demonstracao
    for (int i = 0; i < 32; i++)
        chave[i] = i;

    printf("Digite a mensagem que deseja cifrar: ");

    if (scanf(" %255[^\n]", mensagem) != 1)
        return 1;

    size_t tamanho = strlen(mensagem);

    // Gera nonce aleatorio
    FILE *random = fopen("/dev/urandom", "rb");

    if (random == NULL)
        return 1;

    if (fread(nonce, 1, 12, random) != 12)
    {
        fclose(random);
        return 1;
    }

    fclose(random);

    // Cifra a mensagem
    chacha20((uint8_t *)mensagem, tamanho, chave, nonce);

    printf("\nMensagem cifrada (HEX): ");
    print_hex((uint8_t *)mensagem, tamanho);

    // Salva o nonce e a mensagem cifrada
    FILE *arquivo = fopen("mensagem.bin", "wb");

    if (arquivo == NULL)
    {
        printf("Erro ao criar arquivo.\n");
        return 1;
    }

    int ok = fwrite(nonce, 1, 12, arquivo) == 12 &&
             fwrite(mensagem, 1, tamanho, arquivo) == tamanho;

    if (fclose(arquivo) != 0 || !ok)
    {
        printf("Erro ao salvar arquivo.\n");
        return 1;
    }

    printf("Mensagem salva em mensagem.bin\n");

    return 0;
}
