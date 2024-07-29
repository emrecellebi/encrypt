#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sha1.h"
#include "sha256.h"
#include "md5.h"
#include "crc32c.h"

int main(int argc, char** argv)
{
	if(argc <= 1)
	{
		printf("encrypt : No command specified. Use 'encrypt --help' for a detailed command list");
		return 1;
	}
	
	if(argc == 3 && strcmp(argv[1], "--sha1-ctx") == 0)
	{
		const char* str = argv[2];
		int len = strlen(str);
		
		UL_SHA1_CTX ctx;
		unsigned char digest[UL_SHA1LENGTH];
		
		ul_SHA1Init(&ctx);
		for(unsigned int i = 0; i < len; i += 1)
			ul_SHA1Update(&ctx, (const unsigned char*)str + i, 1);
		ul_SHA1Final(digest, &ctx);
		
		printf("SHA1 Hash: ");
		for(unsigned int i = 0; i < UL_SHA1LENGTH; i++)
			printf("%02x", digest[i]);
		
		return 1;
	}
	
	if(argc == 3 && strcmp(argv[1], "--sha1") == 0)
	{
		const char* str = argv[2];
		int len = strlen(str);
		
		unsigned char hash_out[UL_SHA1LENGTH];
		ul_SHA1((char*)hash_out, str, 3);
		
		printf("SHA1 Hash: ");
		for(unsigned int i = 0; i < UL_SHA1LENGTH; i++)
			printf("%02x", hash_out[i]);
		
		return 1;
	}
	
	if(argc == 3 && strcmp(argv[1], "--sha256-ctx") == 0)
	{
		const char* str = argv[2];
		int len = strlen(str);
		
		unsigned char hash_out[UL_SHA256LENGTH];
		
		sha256 state;
		sha256_init(&state);
		sha256_update(&state, str, len);
		sha256_sum(&state, hash_out);
		
		printf("SHA256 Hash: ");
		for(unsigned int i = 0; i < UL_SHA256LENGTH; i++)
			printf("%02x", hash_out[i]);
		return 1;
	}
	
	if(argc == 3 && strcmp(argv[1], "--sha256") == 0)
	{
		const char* str = argv[2];
		int len = strlen(str);
		
		unsigned char hash_out[UL_SHA256LENGTH];
		ul_SHA256(hash_out, (const unsigned char*)str, len);

		printf("SHA256 Hash: ");
		for(unsigned int i = 0; i < UL_SHA256LENGTH; i++)
			printf("%02x", hash_out[i]);
		return 1;
	}
	
	if(argc == 3 && strcmp(argv[1], "--md5-ctx") == 0)
	{
		const char* str = argv[2];
		int len = strlen(str);
		
		unsigned char hash_out[UL_MD5LENGTH];
		
		UL_MD5_CTX ctx;
		ul_MD5Init(&ctx);
		ul_MD5Update(&ctx, (const unsigned char*)str, (unsigned)len);
		ul_MD5Final(hash_out, &ctx);

		printf("MD5 Hash: ");
		for(unsigned int i = 0; i < UL_MD5LENGTH; i++)
			printf("%02x", hash_out[i]);
		return 1;
	}
	
	if(argc == 3 && strcmp(argv[1], "--md5") == 0)
	{
		const char* str = argv[2];
		size_t len = strlen(str);
		
		unsigned char hash_out[UL_MD5LENGTH];
		ul_MD5(hash_out, (const unsigned char*)str, len);

		printf("MD5 Hash: ");
		for(unsigned int i = 0; i < UL_MD5LENGTH; i++)
			printf("%02x", hash_out[i]);
		return 1;
	}
	
	if(argc == 3 && strcmp(argv[1], "--crc32c") == 0)
	{
		char* ptr = argv[2];
		size_t len = strlen(ptr);
		char data[len + 1];
		strcpy(data, ptr);
		
		//uint32_t hash = ul_crc32c_exclude_offset(0xFFFFFFFF, (const unsigned char*)data, sizeof(data) - 1, 0, 0);
		uint32_t hash = crc32c(0xFFFFFFFF, data, sizeof(data) - 1);
		printf("CRC32C Hash: 0x%X, %d", hash, hash);
		return 1;
	}
	
	if(argc == 2 && strcmp(argv[1], "--help") == 0)
	{
		printf("\nCopyright (c) 2012-2024 Emre Celebi\n\n");
		printf("Usage: encrypt [-options] <parameters>\n");
		printf("   --crc32c <str>\n");
		printf("   --sha1-ctx, --sha1 <str>\n");
		printf("   --sha256-ctx, --sha256 <str>\n");
		printf("   --md5-ctx, --md5 <str>\n");
		printf("   --version\n");
		printf("   --help\n");
		return 1;
	}
	
	if(argc == 2 && strcmp(argv[1], "--version") == 0)
	{
		printf("\nencrypt version: 0.0.2\n");
		printf("Last revised: 30th Jan 2024\n");
		printf("The last version is always avaible\n");
		printf("Created By Emre Celebi\n");
		return 1;
	}
	
	return 0;
}