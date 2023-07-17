# SGX-Bleed Proof-of-Concept codes
This repository contains PoC code for [SGX-Bleed](https://arxiv.org/pdf/1710.09061.pdf).  

After freeing the buffer that stored the secrets without being flushed, if the structure is placed at that location and initialized by assigning it to a member, the structure padding portion is not initialized.  
Therefore, when the structure is returned from Enclave, the secrets that should have been freed leaks by the amount of the padding size.  
  
The author of this repository is not related to the author of the SGX-Bleed article.  


## Operating environment
The author of this repository has confirmed successful execution in the following operating environments:
* **Machine**: Azure DCsv2 VM (vCPU: 4, RAM: 16GiB)
* **OS**: Ubuntu 20.04.6 LTS
* **OpenSSL**: version 1.1.1f  31 Mar 2020
* **SGXSDK**: version 2.19.100.3


## Install
If your environment supports hardware mode, just execute following to build:

```
make
```

If you only can run enclave programs in simulation mode, execute following command to build:

```
make SGX_MODE=SIM
```

## Run program
Run the built program by following command:

```
./app
```

If the program is successfully executed, output like following will be displayed.

```
Execute ECALL.

-----------------------------------------------------------------------------
secret buffer to be leaked by SGX-Bleed (debug display)
-----------------------------------------------------------------------------
0000 - 78 78 78 78 78 78 78 78-78 62 6c 65 65 64 65 64   xxxxxxxxxbleeded
0010 - 78 78 78 78 78 78 78 78-                          xxxxxxxx

=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Bytes of the test_st structure ->

-----------------------------------------------------------------------------
returned structure (the secret bytes are "bleeded")
-----------------------------------------------------------------------------
0000 - 0a 00 00 00 00 00 00 00-14 62 6c 65 65 64 65 64   .........bleeded
0010 - 1e 00 00 00 00 00 00 00-                          ........

Whole operations have been executed successfully.
```


## LICENSE
The BSD license is applied according to the license applied to [the sample codes in Linux-SGX](https://github.com/intel/linux-sgx/blob/master/License.txt).


## References
[1]"Leaking Uninitialized Secure Enclave Memory via Structure Padding", Sangho Lee and Taesoo Kim, https://arxiv.org/pdf/1710.09061.pdf  
[2]"Uninitialized Memory - SGX 101", retrieved July 17, 2023 from https://sgx101.gitbook.io/sgx101/sgx-security/uninitialized-memory