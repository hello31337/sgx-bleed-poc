#include "Enclave_t.h"
#include <sgx_trts.h>
#include <string>
#include <string.h>


test_struct_t ecall_bleed()
{
	uint8_t *secret_buf = (uint8_t*)malloc(24); // buffer to store secret string
	const char *secret_str = "bleeded"; // secret string

	memset(secret_buf, 'x', 9); // fill in the non-leakage area with some letter ('x' here)
	memcpy(secret_buf + 9, secret_str, 7); // set secret string to buffer here
	memset(secret_buf + 16, 'x', 8); // fill in the non-leakage area with some letter ('x' here)

	/* print the bytes of secret buffer by OCALL for debug */
	ocall_debug_print(secret_buf, 24);

	/* get the address of secret buffer so that the address of 
	 * the secret buffer can be traced even after free.
	 * note, however, that even if you simply declare the structure 
	 * without doing anything after deallocation, the structure will often 
	 * be placed at the location where the secret buffer was originally located. */
	uint64_t stale_ptr = (uint64_t)&secret_buf[0];
	
	free(secret_buf);

	/* allocate the structure to the location 
	 * where the secret buffer was located. */
	uint8_t *test_st_buf = (uint8_t*)stale_ptr;
	test_st_buf = (uint8_t*)malloc(24);

	/* initialized by assignment to the members. With this method, 
	 * the padding portion is not initialized, so it leaks on return. */
	test_struct_t *test_st = (test_struct_t*)test_st_buf;
	test_st->a = 10;
	test_st->b = 20;
	test_st->c= 30;

	return *test_st;
}
