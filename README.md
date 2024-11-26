# CoFHE

**Collaborative Fully Homomorphic Encryption (CoFHE)** is the first fully homomorphic encryption scheme designed for secure computations in a threshold distributed setup. CoFHE enables multiple parties to collaboratively perform computations over encrypted data without revealing any underlying information to individual parties.

## Documentation

For detailed documentation, please visit the [OpenVector Documentation](https://openvector.gitbook.io/openvector/).

---

## Usage Instructions

CoFHE is a header-only C++ library, making it easy to integrate into your projects. The library depends on the following libraries:

- **[BICYCL](https://github.com/OpenVectorAI/bicycl)**: For primitives of CPU-Crytosystem(CLHSM2k).
- **[nlohmann/json](https://github.com/nlohmann/json)**: For serialization and deserialization.
- **[boost/asio] - For asynchronous networking.

### Including CoFHE in Your Project

1. **Clone the CoFHE Repository**

   ```bash
   git clone https://github.com/OpenVectorAI/cofhe.git
   ```

2. **Include Headers in Your Source Files**

   In your C++ source files, include the CoFHE headers:

   ```cpp
    #include "cofhe/cofhe.h"
    #include "node/network_details.hpp"
    #include "node/nodes.hpp"
    #include "node/client_node.hpp"
    #include "node/compute_request_handler.hpp"
   ```

### Build Configuration

CoFHE does not require linking against any libraries since it's header-only. Ensure that your compiler supports C++17 or later.

---

## Instructions to Run Benchmarks

CoFHE includes benchmark programs to evaluate the performance of the library both locally and over a network.

### Setup Instructions

1. **Create a Build Directory**

   ```bash
   mkdir build
   cd build
   ```

2. **Configure the Build with CMake**

   ```bash
   cmake ..
   ```

3. **Compile the Examples and Benchmarks**

   ```bash
   make cofhe_examples
   make cofhe_benchmarks
   ```

4. **Prepare the Network Startup Script**

   ```bash
   cp ../scripts/start_network.sh ./cofhe_examples
   ```

5. **Start the CoFHE Network**

   ```bash
   cd cofhe_examples
   chmod +x start_network.sh
   ./start_network.sh
   ```

   This script sets up and starts the CoFHE network required for network benchmarks.

6. **Copy Network Credentials**

   ```bash
   cp ./server.pem ../cofhe_benchmarks
   cd ../cofhe_benchmarks
   ```

   The `server.pem` file contains the server's public key certificate necessary for secure communication.

### Running the Benchmarks

#### Local Benchmark Program

The local benchmark program measures the performance of CoFHE operations without network communication.

1. **Available Modes**

   - `scal_matmul`: Scalar multiplication and matrix multiplication.
   - `ciphertext_matadd`: Homomorphic addition of ciphertext matrices.

2. **Running the Local Benchmark**

   ```bash
   cd build/benchmarks
   ./local scal_matmul
   ```

   Replace `scal_matmul` with the desired mode (`ciphertext_matadd`).

#### Network Benchmark Program

The network benchmark program measures the performance of CoFHE operations involving network communication.

1. **Available Modes**

   - `ciphertext_matmul`: Homomorphic multiplication of ciphertext matrices.
   - `scalar_ciphertext_matmul`: Homomorphic multiplication of ciphertext matrices with scalar values.
   - `ciphertext_matadd`: Homomorphic addition of ciphertext matrices.
   - `decrypt`: Decryption of ciphertexts over the network.

2. **Running the Network Benchmark**

   Ensure the CoFHE network is running before executing network benchmarks.

   ```bash
   cd build/benchmarks
   ./network ciphertext_matmul
   ```

   Replace `ciphertext_matmul` with the desired mode (`scalar_ciphertext_matmul`, `ciphertext_matadd`, `decrypt`).

### Notes

- The `start_network.sh` script must be executed before running network benchmarks.
- The `server.pem` file is required for secure communication with the CoFHE network.
- Use the appropriate mode based on the operation you wish to benchmark.

---

## Example Usage

Here's a simple example demonstrating how to use CoFHE in your project:

```cpp
#include "cofhe/cofhe.h"

int main() {
    // Instantiate the cryptosystem
    CryptoSystem cs;

    // Generate keys
    auto sk = cs.keygen();
    auto pk = cs.keygen(sk);

    // Create plaintexts
    auto pt1 = cs.make_plaintext(10.0f);
    auto pt2 = cs.make_plaintext(20.0f);

    // Encrypt plaintexts
    auto ct1 = cs.encrypt(pk, pt1);
    auto ct2 = cs.encrypt(pk, pt2);

    // Perform homomorphic addition
    auto ct_sum = cs.add_ciphertexts(pk, ct1, ct2);

    // Decrypt the result
    auto pt_sum = cs.decrypt(sk, ct_sum);
    float result = cs.get_float_from_plaintext(pt_sum);

    std::cout << "Homomorphic Addition Result: " << result << std::endl; // Output: 30.0

    return 0;
}
```

---

### Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**: Create a personal fork of the CoFHE repository on GitHub.

2. **Create a Feature Branch**: 

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**: Implement your feature or bug fix.

4. **Commit Changes**:

   ```bash
   git commit -am "Add your commit message here"
   ```

5. **Push to Your Fork**:

   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**: Submit a pull request to the main CoFHE repository.

### License

CoFHE is licensed under the [BSD 3-Clause License]. See the license file for more details.

---

## Contact

For further information or assistance:

- **Email**: [support@openvector.ai](mailto:support@openvector.ai)