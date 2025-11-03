# README lib60870-C                      {#mainpage}

lib60870 library for IEC 60870-5 based protocols in C

The current implementation contains code for the IEC 60870-5-101 (application layer and serial link layer) and IEC 60870-5-104 (protocool over TCP/IP) specifications.

Features:

- support for all application layer message types
- master and slave
- balanced and unbalanced link layers (for CS 101 serial communication)
- client/server for CS 104 TCP/IP communication
- CS 104 redundancy group support
- CS101 slave/CS104 server: file service support
- Supports most TLS features required by IEC 62351-3 (third party code mbedtls required)
- **IEC 62351-5 application layer security with Post-Quantum (PQC) hybrid key exchange (ECDH + Kyber)**
- portable C99 code

Please also consider the User Guide and the API reference documentation (https://support.mz-automation.de/doc/lib60870/latest/)


## Compiling and running the examples:


In the lib60870-C folder build the library with

`make`

Go to the examples folder and build the examples with

`make`

in each examples' directory.

The library and examples can also be build with _CMake_.

To build the library in a separate folder create a new folder as subdirectory of
the project folder and run cmake to create the build files:

`mkdir build`

`cd build`

`cmake ..`

## Building without common code and HAL

The library contains some common code and a platform abstraction layer (HAL) that is shared with
other protocol libraries of MZ Automation (e.g. libiec61850). In order to simplify using these
protocol libraries together it is possible to compile the library without the common parts.

This can be done by using the *WITHOUT_HAL* and *WITHOUT_COMMON* defines when calling make:

`make WITHOUT_HAL=1 WITHOUT_COMMON=1`

## Building with TLS support

The library can be build with support for TLS. In order to do so you have to download mbedtls version 2.28.x.

Unpack the mbedtls tarball in the dependencies folder so that a folder

dependencies/mbedtls-2.28

exists.

The cmake build system will automatically detect the mbedtls source and build the library with TLS support and mbedtls included

When using make you have to call make with WITH_MBEDTLS=1

`make WITH_MBEDTLS=1`

## Building with Post-Quantum Cryptography (PQC) Support

The library supports quantum-resistant cryptography for the IEC 62351-5 application security layer (A-Profile) by implementing a hybrid key exchange mechanism (ECDH + Kyber-768). This provides protection against both classical and future quantum attackers.

To enable this feature, you must first install `liboqs` (Open Quantum Safe). You can find installation instructions on the OQS GitHub page.

Once `liboqs` is installed in a standard system path, the CMake build system will automatically detect it and enable PQC support.

```bash
mkdir build
cd build
cmake .. 
cmake --build .
```

The build log will show `Found liboqs` if the library was detected successfully. The application can then be configured at runtime to use the PQC hybrid key exchange.

## Post-Quantum Cryptography (PQC) Support

lib60870-C now supports Post-Quantum Cryptography for IEC 62351-5 A-Profile security. This implementation provides:

- **Hybrid Key Exchange**: Combines classical ECDH with post-quantum Kyber KEM
- **Three Security Suites**:
  - `0x01`: ECDH-HKDF-AESGCM (classical only)
  - `0x02`: ML-KEM-HKDF-AESGCM (PQC only)
  - `0x03`: HYBRID-(ECDH||ML-KEM)-HKDF-AESGCM
- **KEM_ID Values**:
  - `0x0200`: ML-KEM-512
  - `0x0201`: ML-KEM-768 (default)
  - `0x0202`: ML-KEM-1024

### Configuration

Set security policy in your application:
```c
AProfileContext ctx = AProfile_create(...);
ctx->required_suite = 0x03; // Require hybrid mode
ctx->kem_id = 0x0201;       // Use ML-KEM-768
ctx->role_who_decapsulates = OPTION_1; // Server sends ciphertext
```

### Wire Format

Security objects (TypeID=136) use an enhanced header format:
```
[0] kind: 0xA1 (KEM-PK) or 0xA2 (KEM-CT)
[1-2] total_chunks (uint16 LE)
[3-4] chunk_index (uint16 LE)
[5-6] total_length (uint16 LE)
[7-8] suite_id (uint16 LE)
[9-10] kem_id (uint16 LE)
[11] hash_id
[12..] payload
```

### Key Derivation

Keys are derived using HKDF-SHA256 with:
```
context = "IEC-62351-5-AProfile KEM v1" || suite_id || kem_id
```

## Library configuration

There are different runtime and compile-time configuration options.

Compile time configuration options can be used to shrink down the library for small embedded systems. Compile time configuration can be changed by modifying the file _config/lib60870_config.h_.

## Memory allocation

The library uses dynamic memory allocation (malloc/calloc wrapped by own functions that can be replaced when required).

The CS104 slave uses dynamic memory allocation only at setup time (when calling the function _CS104_Slave_create_ and
_CS104_Slave_start_/_CS104_Slave_startThreadless_.

For details please have a look at the _User Guide_.

## Contact:

The library is developed by Michael Zillgith and supported by MZ Automation GmbH.

For bug reports, hints or support please contact info@mz-automation.de



## Licensing

This software can be dual licensed under the GPLv3 (https://www.gnu.org/licenses/gpl-3.0.en.html) and a commercial license agreement.

When using the library in commercial and non-GPL applications you should buy a commercial license.

## Commercial licenses and support

Support and commercial license options are provided by MZ Automation GmbH. Please contact info@mz-automation.de for more details.

## Contributing

If you want to contribute to the improvement and development of the library please send me comments, feature requests, bug reports, or patches.

For more than trivial contributions I require you to sign a Contributor License Agreement. Please contact info@libiec61850.ccom
