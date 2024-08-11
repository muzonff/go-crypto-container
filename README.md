# go-crypto-container

## Overview

This module provides functionality to securely encrypt and decrypt data using AES encryption with a password-derived key with secure encryption parameters and custom JSON data store. It also includes functionality for securely generating iterations count and bytes (for IV), and handling HMAC check for data integrity.

## Features

- **Encryption and Decryption:** Encrypt plaintext using AES encryption and decrypt it back.
- **HMAC:** Ensure data integrity with HMAC.
- **Random Data Generation:** Generate random bytes (for IV) and iterations.
- **JSON Serialization:** Serialize and deserialize encrypted data to/from JSON format.

## Installation

To use module, include it in your Go project. You can do this by adding it to your module’s dependencies.

### Go Modules

If you are using Go modules, you can include it in your `go.mod` file:

```go
require (
    // Add the module path here
    github.com/muzonff/go-crypto-container v1.0.0
)
```


## Usage

### Encryption and Decryption

#### CreateContainer

```go
package main

import (
    "fmt"
    "github.com/yourusername/container"
)

func main() {
    plaintext := "hello world"
    password := "password123"

    containerJSON, err := container.CreateContainer(plaintext, password)
    if err != nil {
        fmt.Printf("Error creating container: %v\n", err)
        return
    }

    fmt.Println("Encrypted JSON Container:", containerJSON)
}
```

#### DecryptContainer

```go
package main

import (
    "fmt"
    "github.com/yourusername/container"
)

func main() {
    containerJSON := "your-encrypted-json"
    password := "password123"

    decryptedText, err := container.DecryptContainer(containerJSON, password)
    if err != nil {
        fmt.Printf("Error decrypting container: %v\n", err)
        return
    }

    fmt.Println("Decrypted Text:", decryptedText)
}
```

### Secure Random

#### GenerateRandomBytes (uses crypto module random)

```go
package main

import (
    "fmt"
    "github.com/yourusername/container"
)

func main() {
    bytes, err := container.GenerateRandomBytes(16)
    if err != nil {
        fmt.Printf("Error generating random bytes: %v\n", err)
        return
    }

    fmt.Printf("Random Bytes: %x\n", bytes)
}
```

#### Dynamical generate iterations count (result depending on hardware)

```go
package main

import (
    "fmt"
    "github.com/yourusername/container"
)

func main() {
    randomNumber := container.GenerateRandomNumber()
    fmt.Printf("Random Number: %d\n", randomNumber)
}
```

## Testing

To ensure the module functions correctly, you can run the tests using:

```bash
go test ./container -v
```

The tests cover various scenarios including:

- Random byte and iters generation
- Encryption and decryption correctness
- Handling of errors and edge cases

## Error Handling

Functions in this module return errors if get an error while processing. Handling example:
```golang
decryptedText, err := container.DecryptContainer(containerJSON, password)
if err != nil {
    fmt.Printf("Error decrypting container: %v\n", err)
    return
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request to contribute to this project.

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, write an Issue.
