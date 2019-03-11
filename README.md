# SwiftPaillier

An implementation of Paillier's homomorphic encryption in Swift. It's made for scientific purposes, so be careful when using this library.

## Installation via SPM

Declare a dependency on this package inside your `Package.swift`:
```swift
.package(url: "https://github.com/code28/SwiftPaillier.git", from: "1.0.0"),
// ...
.target(..., dependencies: [..., "SwiftPaillier"]),
```

## Usage

```swift
import BigInt
import SwiftPaillier

let crypto = SwiftPaillier()
let cleartext = BigUInt(123456)
let addend = BigUInt(44)

let encryption = crypto.encrypt(cleartext)
encryption.add(addend)
let ciphertext = encryption.ciphertext

let decryptedText = crypto.decrypt(ciphertext: ciphertext)
assert((cleartext + addend) == decryptedText)
```

## License

This package is licensed under the MIT license. By default it uses [GMP](https://gmplib.org/), which is licensed under [GNU LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.de.html), and [BigInt](https://github.com/attaswift/BigInt), which is MIT licensed.

Since GMP is dynamically linked, this conforms to the GNU LGPLv3, but pay attention to the conditions of the LGPLv3 when using this library.

(It is possible to use SwiftPaillier without GMP and only use BigInt, which is slower.)
