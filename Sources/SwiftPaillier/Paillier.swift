//
//  Paillier.swift
//  Created by Simon Kempendorf on 07.02.19.
//

import Foundation
import BigInt
import Bignum

public final class Paillier {
    public static let defaultKeysize = 2048

    private let privateKey: PrivateKey
    public let publicKey: PublicKey

    public init(strength: Int = Paillier.defaultKeysize) {
        let keyPair = Paillier.generateKeyPair(strength)
        privateKey = keyPair.privateKey
        publicKey = keyPair.publicKey
    }

    public init(keyPair: KeyPair) {
        self.privateKey = keyPair.privateKey
        self.publicKey = keyPair.publicKey
    }

    public func L(x: BigUInt, p: BigUInt) -> BigUInt {
        return (x-1)/p
    }

    public func L(x: Bignum, p: Bignum) -> Bignum {
        return (x-1)/p
    }

    public func decrypt(ciphertext: BigUInt, type: DecryptionType = .bigIntDefault) -> BigUInt {
        switch type {
        case .bigIntFast:
            let mp = (L(x: ciphertext.power(privateKey.p - 1, modulus: privateKey.psq), p: privateKey.p) * privateKey.hp) % privateKey.p
            let mq = (L(x: ciphertext.power(privateKey.q - 1, modulus: privateKey.qsq), p: privateKey.q) * privateKey.hq) % privateKey.q

            // Solve using Chinese Remainder Theorem
            let u = (mq-mp) * privateKey.pinv
            return mp + ((u % privateKey.q) * privateKey.p)
        case .bigIntDefault:
            let lambda = (privateKey.p-1)*(privateKey.q-1)
            let mu = L(x: publicKey.g.power(lambda.magnitude, modulus: publicKey.nsq), p: publicKey.n).inverse(publicKey.n)!
            return (L(x: ciphertext.power(lambda, modulus: publicKey.nsq), p: publicKey.n) * mu) % publicKey.n
        case .bigNumFast:
            let ciphertext = Bignum(ciphertext.description)
            let mp = (L(x: mod_exp(ciphertext, privateKey.pnum - 1, privateKey.psqnum), p: privateKey.pnum) * privateKey.hpnum) % privateKey.pnum
            let mq = (L(x: mod_exp(ciphertext, privateKey.qnum - 1, privateKey.qsqnum), p: privateKey.qnum) * privateKey.hqnum) % privateKey.qnum

            // Solve using Chinese Remainder Theorem
            let u = (mq-mp) * privateKey.pinvnum
            return BigUInt((mp + ((u % privateKey.qnum) * privateKey.pnum)).string())!
        case .bigNumDefault:
            let ciphertext = Bignum(ciphertext.description)
            let lambda = (privateKey.pnum-1)*(privateKey.qnum-1)
            let mu = inverse(L(x: mod_exp(publicKey.gnum, lambda, publicKey.nsqnum), p: publicKey.nnum), publicKey.nnum)!
            return BigUInt(((L(x: mod_exp(ciphertext, lambda, publicKey.nsqnum), p: publicKey.nnum) * mu) % publicKey.nnum).string())!
        }
    }

    public func decrypt(_ encryption: PaillierEncryption, type: DecryptionType = .bigIntDefault) -> BigUInt {
        return decrypt(ciphertext: encryption.ciphertext, type: type)
    }

    public func encrypt(_ plaintext: BigUInt) -> PaillierEncryption {
        return PaillierEncryption(plaintext, for: publicKey)
    }

    public enum DecryptionType {
        case bigIntDefault
        case bigIntFast
        case bigNumDefault
        case bigNumFast
    }
}

// MARK: Keys and their handling
public extension Paillier {
    struct KeyPair {
        public let privateKey: PrivateKey
        public let publicKey: PublicKey
    }

    struct PublicKey: Codable {
        let n: BigUInt
        let g: BigUInt

        // MARK: Precomputed values
        let nsq: BigUInt
        let nnum: Bignum
        let gnum: Bignum
        let nsqnum: Bignum

        init(n: BigUInt, g: BigUInt) {
            self.n = n
            self.g = g
            nsq = n.power(2)
            nnum = Bignum(n.description)
            gnum = Bignum(g.description)
            nsqnum = Bignum(nsq.description)
        }
    }

    struct PrivateKey {
        let p: BigUInt
        let q: BigUInt

        // MARK: Precomputed values
        let psq: BigUInt
        let qsq: BigUInt
        let hp: BigUInt
        let hq: BigUInt
        let pinv: BigUInt

        let pnum: Bignum
        let qnum: Bignum
        let psqnum: Bignum
        let qsqnum: Bignum
        let hpnum: Bignum
        let hqnum: Bignum
        let pinvnum: Bignum

        init(p: BigUInt, q: BigUInt, g: BigUInt) {
            self.p = p
            self.q = q
            psq = p.power(2)
            qsq = q.power(2)
            hp = Paillier.h(on: g, p: p, psq: psq)
            hq = Paillier.h(on: g, p: q, psq: qsq)
            pinv = p.inverse(q)!

            pnum = Bignum(p.description)
            qnum = Bignum(q.description)
            psqnum = Bignum(psq.description)
            qsqnum = Bignum(qsq.description)
            hpnum = Bignum(hp.description)
            hqnum = Bignum(hq.description)
            pinvnum = Bignum(pinv.description)
        }
    }

    static func h(on g: BigUInt, p: BigUInt, psq: BigUInt) -> BigUInt {
        let parameter = g.power(p-1, modulus: psq) % psq
        let lOfParameter = (parameter-1)/p
        return lOfParameter.inverse(p)!
    }

    static func generatePrime(_ width: Int) -> BigUInt {
        while true {
            var random = BigUInt.randomInteger(withExactWidth: width)
            random |= BigUInt(1)
            if Bignum(random.description).isPrime(rounds: 30) {
                return random
            }
        }
    }

    static func generateKeyPair(_ strength: Int = Paillier.defaultKeysize) -> KeyPair {
        var p, q: BigUInt
        p = generatePrime(strength/2)
        repeat {
            q = generatePrime(strength/2)
        } while p == q

        if q < p {
            swap(&p, &q)
        }

        let n = p*q
        let g = n+1

        let privateKey = PrivateKey(p: p, q: q, g: g)
        let publicKey = PublicKey(n: n, g: g)
        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }
}

public class PaillierEncryption {
    private var _ciphertext: Bignum
    public var ciphertext: BigUInt {
        get {
            if !isBlinded {
                blind()
            }
            return BigUInt(self._ciphertext.string())!
        }
    }
    private var isBlinded: Bool
    public let publicKey: Paillier.PublicKey

    public init(_ plaintext: BigUInt, for publicKey: Paillier.PublicKey) {
        self.publicKey = publicKey
        self._ciphertext = Bignum(0)
        self.isBlinded = false
        encrypt(plaintext)
    }

    public init(ciphertext: BigUInt, for publicKey: Paillier.PublicKey) {
        self.publicKey = publicKey
        self._ciphertext = Bignum(ciphertext.description)
        isBlinded = false
    }

    private func encrypt(_ plaintext: BigUInt) {
        let plaintextnum = Bignum(plaintext.description)
        _ciphertext = rawEncrypt(plaintextnum)
        isBlinded = false
    }

    private func rawEncrypt(_ plaintext: Bignum) -> Bignum {
        // Shortcut solution:
        return (plaintext * publicKey.nnum + 1) % publicKey.nsqnum

        // General (default) solution:
        // _ciphertext = publicKey.g.power(plaintext, modulus: publicKey.nsq)
    }

    private func rawBlind(_ ciphertext: Bignum) -> Bignum {
        let r = Bignum(BigUInt.randomInteger(lessThan: publicKey.n).description)
        let cipher = ciphertext * mod_exp(r, publicKey.nnum, publicKey.nsqnum)
        return cipher % publicKey.nsqnum
    }

    public func blind() {
        _ciphertext = rawBlind(_ciphertext)
        isBlinded = true
    }

    @discardableResult
    public func add(_ scalar: Bignum) -> PaillierEncryption {
        let ciphertext = rawEncrypt(scalar)
        add(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func subtract(_ scalar: Bignum) -> PaillierEncryption {
        let ciphertext = rawEncrypt(scalar)
        subtract(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func add(_ scalar: BigUInt) -> PaillierEncryption {
        let ciphertext = rawEncrypt(Bignum(scalar.description))
        add(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func subtract(_ scalar: BigUInt) -> PaillierEncryption {
        let ciphertext = rawEncrypt(Bignum(scalar.description))
        subtract(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func subtract(ciphertext: BigUInt) -> PaillierEncryption {
        subtract(ciphertext: Bignum(ciphertext.description))
        return self
    }

    @discardableResult
    public func add(ciphertext: BigUInt) -> PaillierEncryption {
        add(ciphertext: Bignum(ciphertext.description))
        return self
    }

    @discardableResult
    public func subtract(ciphertext: Bignum) -> PaillierEncryption {
        add(ciphertext: inverse(ciphertext, publicKey.nsqnum)!)
        return self
    }

    @discardableResult
    public func add(ciphertext: Bignum) -> PaillierEncryption {
        _ciphertext = (_ciphertext * ciphertext) % publicKey.nsqnum
        isBlinded = false
        return self
    }

    @discardableResult
    public func multiply(_ scalar: BigUInt) -> PaillierEncryption {
        multiply(Bignum(scalar.description))
        return self
    }

    @discardableResult
    public func multiply(_ scalar: Bignum) -> PaillierEncryption {
        _ciphertext = mod_exp(_ciphertext, scalar, publicKey.nsqnum)
        isBlinded = false
        return self
    }
}
