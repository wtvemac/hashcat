#define LTM_DESC

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <tomcrypt.h>
#include "crack_wtv_privkey.h"

// gcc crack_wtv_privkey.cpp -O3 -ltomcrypt -lcrypto -Wdeprecated-declarations -o cwk

#define MIN_PASSLEN 3
#define MAX_PASSLEN 16
// Every 10 million tries, tell the user our progress
#define PRINT_INTERVAL 10000000

#define SINGLE_TESTS 1
#define SINGLE_TEST_DATA_BEFORE "\x30\x82\x03\xa7\x02\x01\x00\x30"
#define SINGLE_TEST_DATA_AFTER  "\xc9\x12\x0e\xde\x02\x1b\x5a\xc4"
#define PRINT_DEBUG 0
#define DECRYPT_TEST 0
#define ENCRYPT_TEST 0

char characters[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_-+=";
//char characters[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
//char characters[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!-";

// File needs to exist, otherwise crash
#if DECRYPT_TEST == 1
const char* encrypted_key_file_path = "./prodPrivate.enct.enc";
#elif ENCRYPT_TEST == 1
const char* encrypted_key_file_path = "./TEST_prodPrivate.der";
#else
const char* encrypted_key_file_path = "./prodPrivate.der.enc";
#endif

symmetric_CBC cbc;
int cipher_idx;

unsigned char* password_key;
size_t password_key_size;
unsigned char* password_iv;
size_t password_iv_size;

unsigned int data_size;
unsigned char* in_data;
unsigned char* out_data;

unsigned int tries = 0;

inline bool check_sha1_filled_key()
{
	DES_cblock key1, key2, key3, iv_cblock;
	DES_key_schedule schedule1, schedule2, schedule3;

	memcpy((password_key + sha1_desc.hashsize), password_key, (password_key_size - sha1_desc.hashsize));

	// The DES key is 24 bytes.
	// The first 20 bytes is the SHA1 of the password, then the first 4 SHA1 bytes is repeated at the end to cover the last 4 characters.
	memcpy(&key1, password_key, sizeof(key1));
	memcpy(&key2, (password_key + 8), sizeof(key2));
	memcpy(&key3, (password_key + 16), sizeof(key3));

	#if PRINT_DEBUG == 1
	printf("password_key = '");
	for(int i = 0; i < password_key_size; i++)
	{
		printf("%02x", password_key[i]);
	}
	printf("'\n");
	#endif

	// DES IV is 8 characters and is just a copy the password key starting 2 bytes in (SHA1 of the password + 2 ... SHA1 of the password + 10)
	memcpy(&iv_cblock, (password_key + 2), sizeof(iv_cblock));
	//memset(&iv_cblock, 0, sizeof(iv_cblock));

	DES_test_key(&key1, &schedule1);
	DES_test_key(&key2, &schedule2);
	DES_test_key(&key3, &schedule3);

	#if SINGLE_TESTS == 1
	printf("SHA1='");
	for(int i = 0; i < sha1_desc.hashsize; i++)
	{
		printf("%02x", password_key[i]);
	}
	#else
	#if DECRYPT_TEST == 1
	// Decrypt test:
	printf("SHA1='");
	for(int i = 0; i < sha1_desc.hashsize; i++)
	{
		printf("%02x", password_key[i]);
	}
	printf("' --- CHECK_IN: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x", *in_data, *(in_data + 1), *(in_data + 2), *(in_data + 3), *(in_data + 4));
	DES_ede3_cbc_encrypt(in_data, out_data, data_size, &schedule1, &schedule2, &schedule3, &iv_cblock, DES_DECRYPT);
	printf(" --- CHECK_OUT: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x\n\n", *out_data, *(out_data + 1), *(out_data + 2), *(out_data + 3), *(out_data + 4));
	FILE* f = fopen("prodPrivate.dect.enc", "wb");
	fwrite(out_data, 1, data_size, f);
	fclose(f);
	exit(0);
	#endif

	#if ENCRYPT_TEST == 1
	// Encrypt test:
	printf("SHA1='");
	for(int i = 0; i < sha1_desc.hashsize; i++)
	{
		printf("%02x", password_key[i]);
	}
	printf("' --- CHECK_IN: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x", *in_data, *(in_data + 1), *(in_data + 2), *(in_data + 3), *(in_data + 4));
	DES_ede3_cbc_encrypt(in_data, out_data, data_size, &schedule1, &schedule2, &schedule3, &iv_cblock, DES_ENCRYPT);
	printf(" --- CHECK_OUT: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x\n\n", *out_data, *(out_data + 1), *(out_data + 2), *(out_data + 3), *(out_data + 4));
	FILE* f = fopen("prodPrivate.enct.enc", "wb");
	fwrite(out_data, 1, data_size, f);
	fclose(f);
	exit(0);
	#endif
	#endif


	// Try to decrypt private key with generated key (SHA1 transformation of password)
	#if SINGLE_TESTS == 1
	printf("', iv='");
	for(int i = 0; i < sizeof(iv_cblock); i++)
	{
		printf("%02x", *(iv_cblock + i));
	}
	DES_ede3_cbc_encrypt(in_data, out_data, data_size, &schedule1, &schedule2, &schedule3, &iv_cblock, DES_DECRYPT);
	printf("'\n\tDECRYPT: in='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(in_data + i));
	}
	printf("', out='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(out_data + i));
	}
	printf("', out_without_iv='");
	memcpy(&iv_cblock, (password_key + 2), sizeof(iv_cblock));
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(out_data + i) ^ iv_cblock[i]);
	}
	unsigned char* before_data_test = (unsigned char*)malloc(data_size + 1);
	unsigned char* after_data_test = (unsigned char*)malloc(data_size + 1);
	memcpy(before_data_test, SINGLE_TEST_DATA_BEFORE, data_size);
	//DES_ede3_cbc_encrypt(before_data_test, after_data_test, data_size, &schedule1, &schedule2, &schedule3, &iv_cblock, DES_ENCRYPT);
	printf("'\n\tENCRYPT: in='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}

	*(uint32_t *)(before_data_test + 0) = *(uint32_t *)(before_data_test + 0) ^ *(uint32_t *)(iv_cblock + 0);
	*(uint32_t *)(before_data_test + 4) = *(uint32_t *)(before_data_test + 4) ^ *(uint32_t *)(iv_cblock + 4);
	printf("', ^iv='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}
	memset(&iv_cblock, 0, sizeof(iv_cblock));

	/*
	printf("'\n");
	DES_test((DES_LONG *)before_data_test, &schedule1, DES_ENCRYPT);
	printf("\t\tTEST: '");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}
	memset(&iv_cblock, 0, sizeof(iv_cblock));
	printf("'\n");
	for(int i = 0; i < 16; i++)
	{
		printf("\t\tK[%d]='c=%08x d=%08x'\n", i, schedule1.ks[i].deslong[0], schedule1.ks[i].deslong[1]);
	}
	printf("\t\tkey1='");
	for(int i = 0; i < sizeof(key1); i++)
	{
		printf("%02x", *(key1 + i));
	}
	*/

	DES_LONG *data = (DES_LONG *)before_data_test;
	register DES_LONG l, r;
	l = data[0];
	r = data[1];
	IP(l, r);
	data[0] = l;
	data[1] = r;
	printf("', inip='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}
	DES_test(data, &schedule1, DES_ENCRYPT);
	printf("', out1='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}
	DES_test(data, &schedule2, DES_DECRYPT);
	printf("', out2='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}
	DES_test(data, &schedule3, DES_ENCRYPT);
	printf("', out3='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}
	l = data[0];
	r = data[1];
	FP(r, l);
	data[0] = l;
	data[1] = r;

	printf("', out_fp='");
	for(int i = 0; i < data_size; i++)
	{
		printf("%02x", *(before_data_test + i));
	}
	printf("'\n");
	#else
	DES_ede3_cbc_encrypt(in_data, out_data, 8, &schedule1, &schedule2, &schedule3, &iv_cblock, DES_DECRYPT);
	#endif

	// Check first few characters of decrypted data to see if it looks like a valid RSA key.
	return (*out_data == 0x30	  // 0x30: ASN.1 sequence
		&& *(out_data + 1) == 0x82 // 0x82: Long form length, with the next two bytes for the total length
		&& *(out_data + 2) == 0x03 // 0x03 0xa7: Total length is between 935
		&& *(out_data + 3) == 0xa7
		&& *(out_data + 4) == 0x02 // 0x02 0x01 0x00: an ASN.1 tag, this is a PKCS#1 private key
		&& *(out_data + 5) == 0x01
		&& *(out_data + 6) == 0x00
		&& *(out_data + 7) == 0x30 // 0x30: ASN.1 sequence
	);
}

inline bool check_raw_sha1(unsigned char* raw_sha1)
{
	memcpy(password_key, raw_sha1, sha1_desc.hashsize);

	if(check_sha1_filled_key())
	{
		#if SINGLE_TESTS != 1
		printf("POSSIBLE SHA1 '");
		for(int i = 0; i < sha1_desc.hashsize; i++)
		{
			printf("%02x", password_key[i]);
		}
		printf("' CHECK: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x\n\n", *out_data, *(out_data + 1), *(out_data + 2), *(out_data + 3), *(out_data + 4));

		FILE *flog;
		flog = fopen("try_log.log", "a+");
		if(flog != NULL)
		{
			fprintf(flog, "POSSIBLE SHA1 '");
			for(int i = 0; i < sha1_desc.hashsize; i++)
			{
				fprintf(flog, "%02x", password_key[i]);
			}
			fprintf(flog, "' CHECK: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x\n", *out_data, *(out_data + 1), *(out_data + 2), *(out_data + 3), *(out_data + 4));
		}
		fclose(flog);
		#else
		printf("\tFOUND POSSIBLE MATCH!\n");
		#endif

		return true;
	}
	else
	{
		return false;
	}
}

uint8_t hex_to_raw_byte(char hex_number)
{
	if(hex_number >= '0' && hex_number <= '9')
	{
		return hex_number - '0';
	}
	else if(hex_number >= 'A' && hex_number <= 'F')
	{
		return hex_number - 'A' + 10;
	}
	else if(hex_number >= 'a' && hex_number <= 'f')
	{
		return hex_number - 'a' + 10;
	}
	else
	{
		return 0;
	}
}

bool check_str_sha1(const char* sha1_str)
{
	unsigned char raw_sha1[sha1_desc.hashsize];

	for(int i = 0; i < sha1_desc.hashsize; i++)
	{
		raw_sha1[i] = (hex_to_raw_byte(*sha1_str) << 4) | hex_to_raw_byte(*(sha1_str + 1));

		sha1_str += 2;
	}

	return check_raw_sha1(&raw_sha1[0]);
}

inline bool check_password(unsigned char *password, unsigned int passlen)
{
	// Get SHA1 of password
	hash_state md;

	sha1_init(&md);
	sha1_process(&md, password, passlen);
	sha1_done(&md, password_key);

	if(check_sha1_filled_key())
	{
		#if SINGLE_TESTS != 1
		printf("POSSIBLE PASSWORD.%u! '%s' SHA1='", passlen, password);
		for(int i = 0; i < sha1_desc.hashsize; i++)
		{
			printf("%02x", password_key[i]);
		}
		printf("' CHECK: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x\n\n", *out_data, *(out_data + 1), *(out_data + 2), *(out_data + 3), *(out_data + 4));

		FILE *flog;
		flog = fopen("try_log.log", "a+");
		if(flog != NULL)
		{
			fprintf(flog, "POSSIBLE PASSWORD.%u! '%s' SHA1='", passlen, password);
			for(int i = 0; i < sha1_desc.hashsize; i++)
			{
				fprintf(flog, "%02x", password_key[i]);
			}
			fprintf(flog, "' CHECK: 0x%02x | 0x%02x | 0x%02x%02x | 0x%02x\n", *out_data, *(out_data + 1), *(out_data + 2), *(out_data + 3), *(out_data + 4));
		}
		fclose(flog);
		#else
		printf("\tFOUND POSSIBLE MATCH!\n");
		#endif

		return true;
	}
	else
	{
		return false;
	}
}

void setup_crypto()
{
	ltc_mp = ltm_desc;

	password_key_size = sha1_desc.hashsize + 4; // 24 characters. First 20 (sha1_desc.hashsize) chars is the SHA1 of the password, then the first 4 of the SHA1 is repeated
	password_iv_size = 8; // 8 chars, starting at 2 characters into the SHA1 of the password.
	password_key = (unsigned char*)malloc(password_key_size);
	password_iv = (unsigned char*)malloc(password_iv_size);

	register_cipher(&des3_desc);

	cipher_idx = find_cipher("3des");
}

void setup_data()
{
	#if SINGLE_TESTS == 1
	data_size = strlen(SINGLE_TEST_DATA_AFTER);
	in_data = (unsigned char*)malloc(data_size + 1);
	out_data = (unsigned char*)malloc(data_size + 1);
	memcpy(in_data, SINGLE_TEST_DATA_AFTER, data_size);
	#else
	FILE* f = fopen(encrypted_key_file_path, "rb");
	fseek(f, 0, SEEK_END);
	data_size = ftell(f);
	// Set up data sizes based on encrypted key size.
	in_data = (unsigned char*)malloc(data_size + 1);
	out_data = (unsigned char*)malloc(data_size + 1);
	fseek(f, 0, SEEK_SET);
	// Load in encrypted private key
	fread(in_data, 1, data_size, f);
	fclose(f);
	#endif
}

char find_passpos(const char passchar)
{
	size_t character_count = strlen(characters);

	for(int i = 0x00; i < character_count; i++)
	{
		if(characters[i] == passchar)
		{
			return i;
		}
	}

	return 0x00;
}

double tdiff(struct timeval t0, struct timeval t1)
{
	return (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1000000.0f;
}

void run_bruteforce_password_cracker(const char* starting_password)
{
	int character_count = strlen(characters);
	int max_password_index = (MAX_PASSLEN - 1);

	unsigned char password[MAX_PASSLEN + 1]; // +1 for null
	unsigned char passpos[MAX_PASSLEN];

	memset(password, 0, sizeof(password));
	memset(passpos, 0, sizeof(passpos));

	int cur_passlen = MIN_PASSLEN;

	if(starting_password != 0)
	{
		cur_passlen = strlen(starting_password);
		if(cur_passlen > MAX_PASSLEN)
		{
			cur_passlen = MAX_PASSLEN;
		}

		for(int i = (cur_passlen - 1); i >= 0; i--)
		{
			passpos[(MAX_PASSLEN - 1) - i] = find_passpos(*(starting_password + (cur_passlen - (i + 1))));
		}
	}

	bool rollover = false;
	bool first_pass = true;

	struct timeval t0;
	gettimeofday(&t0, 0);

	int cur_min_passlen = (MAX_PASSLEN - cur_passlen);

	while(true)
	{
		for(int i = max_password_index; i >= cur_min_passlen; i--)
		{
			if(rollover)
			{
				rollover = false;

				passpos[i]++;

				if(passpos[i] == character_count)
				{
					int rollover_passlen = (MAX_PASSLEN - i);

					if(rollover_passlen == cur_passlen)
					{
						cur_passlen++;
						
						if(cur_passlen > MAX_PASSLEN)
						{
							printf("NO PASSWORDS FOUND!\n");
							exit(0);
						}
						else
						{
							cur_min_passlen = (MAX_PASSLEN - cur_passlen);
							memset(&passpos[i - 1], 0, cur_passlen);
							first_pass = true;
						}
					}
					else
					{
						memset((passpos + i), 0, rollover_passlen);
						rollover = true;
					}
				}
			}

			password[i] = characters[passpos[i]];

			if(!rollover && !first_pass)
				break;
		}

		first_pass = false;

		tries++;
		if(tries == PRINT_INTERVAL)
		{
			struct timeval t1;
			gettimeofday(&t1, 0);

			unsigned int ntime = time(NULL);
			double crate = PRINT_INTERVAL / tdiff(t0, t1);

			printf("p.%u '%s' ~%f/sec\n", cur_passlen, &password[MAX_PASSLEN - cur_passlen], crate);

			tries = 0;
			t0 = t1;
		}

		check_password(&password[MAX_PASSLEN - cur_passlen], cur_passlen);

		rollover = true;
	}
}

void badtestargs(int argc, char* argv[])
{
	printf("Bad args!\n\n");
	printf("Use to test plaintext password:\n\t%s -p password_text\n", argv[0]);
	printf("Use to test password in hex:\n\t%s -ph password_hex\n", argv[0]);
	printf("Use to test plaintext password:\n\t%s -ps password_sha1\n", argv[0]);
}

void tests(int argc, char* argv[])
{

	if(argc > 2)
	{
		if(!strcmp(argv[1], "-p"))
		{
			check_password((unsigned char*)argv[2], strlen(argv[2]));
			printf("Test done...\n");
		}
		else if(!strcmp(argv[1], "-ph"))
		{
			unsigned char* password_hex = (unsigned char*)argv[2];
			size_t passlen = strlen(argv[2]) / 2;

			unsigned char* password = (unsigned char*)malloc(passlen + 1);

			for(int i = 0; i < passlen; i++)
			{
				password[i] = (hex_to_raw_byte(*password_hex) << 4) | hex_to_raw_byte(*(password_hex + 1));

				password_hex += 2;
			}
			password[passlen] = 0x00;

			check_password(password, passlen);
			printf("Test done...\n");
		}
		else if(!strcmp(argv[1], "-ps"))
		{
			if(strlen(argv[2]) == (sha1_desc.hashsize * 2))
			{
				if(!check_str_sha1(argv[2]))
				{
					printf("SHA1 didn't match!\n");
				}
			}
			else
			{
				printf("Bad SHA1!\n");
			}

			printf("Test done...\n");
		}
		else
		{
			badtestargs(argc, argv);
		}
	}
	else
	{
		badtestargs(argc, argv);
	}
}

void rotate_sptrans()
{
	/*
Kc[0] = 232f2923 : 8cbca48c --
Kc[1] = 390a0812 : e4282048
Kc[2] = 1a230835 : 688c20d4 --
Kc[3] = 2f170400 : bc5c1000
Kc[4] = 1d1e1115 : 74784454 --
Kc[5] = 1b2a3529 : 6ca8d4a4
Kc[6] = 31330608 : c4cc1820 --
Kc[7] = 2d072b32 : b41cacc8
Kc[8] = 073f0a00 : 1cfc2800 --
Kc[9] = 2e391233 : b8e448cc
Kc[10] = 3c3d042b : f0f410ac --
Kc[11] = 370f1410 : dc3c5040
Kc[12] = 073f211d : 1cfc8474 --
Kc[13] = 3e3d2404 : f8f49010
Kc[14] = 2c3c0b00 : b0f02c00 --
Kc[15] = 3d3e2228 : f4f888a0

u:(l:9cd5cb82 ^ Kc:b0f02c00) => 2c25e782
DES_BOX (((u:2c25e782 >>  2) & 0x3f) => 00000020, 0, s_SPtrans) => 00000000

u:(l:96136f64 ^ Kc:1cfc8474) => 8aefeb10
DES_BOX (((u:8aefeb10 >>  2) & 0x3f) => 00000004, 0, s_SPtrans) => 02000000

u:(l:f70f8bdf ^ Kc:f0f410ac) => 07fb9b73
DES_BOX (((u:07fb9b73 >>  2) & 0x3f) => 0000001c, 0, s_SPtrans) => 00000800

u:(l:185ab029 ^ Kc:1cfc2800) => 04a69829
DES_BOX (((u:04a69829 >>  2) & 0x3f) => 0000000a, 0, s_SPtrans) => 02080000

u:(l:323c4748 ^ Kc:c4cc1820) => f6f05f68
DES_BOX (((u:f6f05f68 >>  2) & 0x3f) => 0000001a, 0, s_SPtrans) => 00080800

u:(l:c86f5813 ^ Kc:74784454) => bc171c47
DES_BOX (((u:bc171c47 >>  2) & 0x3f) => 00000011, 0, s_SPtrans) => 00000002

u:(l:254bfd58 ^ Kc:688c20d4) => 4dc7dd8c
DES_BOX (((u:4dc7dd8c >>  2) & 0x3f) => 00000023, 0, s_SPtrans) => 00080002

u:(l:543fbee1 ^ Kc:8cbca48c) => d8831a6d [771097C2] 0x80020200 0x00080802
DES_BOX (((u:d8831a6d >>  2) & 0x3f) => 0000001b, 0, s_SPtrans) => 02080002


	*/

	uint32_t cool = 0xf1e2d3c4;
	/*

	og:    11110001111000101101001111000100

	s4: 0000|1111000111100010110100111100
	r4: 0100|11|11000111100010110100111100
*/
printf("cool=%08x\n", ROTATE(cool, 4));
	exit(0);

	for(int i = 0; i < 8; i++)
	{
		printf("  {\n    ");
		for(int j = 0; j < 64; j++)
		{
			//uint32_t s = ROTATE(DES_SPtrans[i][j], 2);
			uint32_t s = ROTATE(DES_SPtrans[i][j], 6);
			printf("0x%08x,", s);

			if(!((j+1)%4))
			{
				if((j+1) == 64)
					printf("\n");
				else
					printf("\n    ");
			}
		}
		printf("  },\n");
	}

	exit(0);
}

int main(int argc, char* argv[])
{
	//rotate_sptrans();

	setup_crypto();
	setup_data();

	#if SINGLE_TESTS == 1
	tests(argc, argv);
	#else

	if(argc > 2)
	{
	}
	else if(argc == 2)
	{
		if(strlen(argv[1]) == (sha1_desc.hashsize * 2))
		{
			// If first arg is 'sha1_desc.hashsize * 2' chars (40 chars, 2 hex chars per byte) then it's a SHA1 check. Only can check 1 SHA1 hash at a time.
			if(!check_str_sha1(argv[1]))
			{
				printf("SHA1 didn't match!\n");
			}
		}
		else
		{
			// otherwise argv[1] is a starting password (possibly because we're resuming)
			run_bruteforce_password_cracker(argv[1]);
		}
	}
	else
	{
		// Start fresh
		run_bruteforce_password_cracker(0);
	}
	#endif
}
