"""
Toy RSA: key generation, encryption, decryption, and rebuilding a private key from the factors of N.

This is "textbook RSA" with tiny primes (like 3 and 5), written to show how RSA works.
It is NOT secure and must never be used to protect anything:
  - Real RSA uses primes hundreds of digits long (N is 2048+ bits), not single digits.
  - Real RSA adds random padding (OAEP) before encrypting. Without it, the same message
    always encrypts to the same ciphertext, which leaks information.

The whole idea in four lines:
  N = p * q                     (public: anyone can see N)
  phi = (p - 1) * (q - 1)       (secret: you need p and q to compute it)
  e * d = 1  (mod phi)          (e is public, d is the private key)
  encrypt: c = m^e mod N        decrypt: m = c^d mod N
"""

from dataclasses import dataclass
from math import gcd


@dataclass(frozen=True)
class PublicKey:
    """The part of the key you can publish. Anyone can use it to encrypt messages to you."""

    n: int  # the modulus, N = p * q
    e: int  # the public exponent


@dataclass(frozen=True)
class PrivateKey:
    """The secret part. Only the owner should have it; it decrypts messages."""

    n: int  # the same modulus N
    d: int  # the private exponent


def is_prime(k: int) -> bool:
    """Return True if k is prime, by checking every possible divisor up to sqrt(k).

    This is fine for toy numbers. For a 2048-bit N, this kind of search would take
    longer than the age of the universe, which is exactly why RSA works.
    """
    if k < 2:
        return False
    divisor = 2
    while divisor * divisor <= k:
        if k % divisor == 0:
            return False
        divisor += 1
    return True


def _check_primes(p: int, q: int) -> None:
    """Raise ValueError unless p and q are two different primes."""
    if not is_prime(p) or not is_prime(q):
        raise ValueError(f"p and q must both be prime (got p={p}, q={q})")
    if p == q:
        # With p == q the formula for phi below would be wrong, and N = p^2 is trivial to factor.
        raise ValueError("p and q must be different primes")


def _phi(p: int, q: int) -> int:
    """Euler's totient of N = p * q: how many numbers from 1 to N share no factor with N.

    For two different primes this is simply (p - 1) * (q - 1).
    Computing it requires knowing p and q. That is the secret RSA relies on.
    """
    return (p - 1) * (q - 1)


def _private_exponent(e: int, phi: int) -> int:
    """Find d such that (e * d) % phi == 1, i.e. d is the "modular inverse" of e.

    Python's built-in pow(e, -1, phi) does this with the extended Euclidean algorithm,
    which is very fast even for huge numbers, as long as you know phi.
    """
    if gcd(e, phi) != 1:
        # If e and phi share a factor, no inverse exists and decryption would be impossible.
        raise ValueError(f"e={e} must share no common factor with phi={phi}")
    return pow(e, -1, phi)


def generate_keypair(p: int, q: int, e: int | None = None) -> tuple[PublicKey, PrivateKey]:
    """Build an RSA key pair from two different primes p and q.

    If e is not given, pick the smallest e > 1 that shares no factor with phi.
    (Real systems almost always use e = 65537, but that is far larger than our tiny N.)
    """
    _check_primes(p, q)

    # Step 1: the public modulus.
    n = p * q

    # Step 2: phi(N). Easy for us, because we chose p and q.
    phi = _phi(p, q)

    # Step 3: choose the public exponent e.
    if e is None:
        e = 2
        while gcd(e, phi) != 1:
            e += 1
    if not 1 < e < phi:
        raise ValueError(f"e must be between 1 and phi={phi} (got e={e})")

    # Step 4: the private exponent d, the inverse of e modulo phi.
    d = _private_exponent(e, phi)

    return PublicKey(n=n, e=e), PrivateKey(n=n, d=d)


def encrypt(message: int, public_key: PublicKey) -> int:
    """Encrypt an integer message: c = m^e mod N.

    The message must be a whole number from 0 to N - 1, because everything is computed
    "mod N" and larger numbers would wrap around and be lost.
    """
    if not 0 <= message < public_key.n:
        raise ValueError(f"message must be between 0 and {public_key.n - 1} (got {message})")
    # pow(base, exponent, modulus) computes (base ** exponent) % modulus efficiently.
    return pow(message, public_key.e, public_key.n)


def decrypt(ciphertext: int, private_key: PrivateKey) -> int:
    """Decrypt a ciphertext: m = c^d mod N.

    This works because (m^e)^d = m^(e*d), and e*d = 1 + k*phi for some whole number k.
    Euler's theorem says raising to a multiple of phi "cancels out" mod N, leaving m.
    """
    if not 0 <= ciphertext < private_key.n:
        raise ValueError(f"ciphertext must be between 0 and {private_key.n - 1} (got {ciphertext})")
    return pow(ciphertext, private_key.d, private_key.n)


def rebuild_private_key(n: int, e: int, p: int, q: int) -> PrivateKey:
    """The attacker's step: given the public key (n, e) and the factors p, q, recover d.

    This is the same math as generate_keypair. Nothing here is hard; the only thing
    standing between an attacker and d is not knowing p and q. Shor's algorithm
    (Milestone 3) is what finds p and q.
    """
    _check_primes(p, q)
    if p * q != n:
        raise ValueError(f"{p} * {q} = {p * q}, which is not N = {n}")
    phi = _phi(p, q)
    d = _private_exponent(e, phi)
    return PrivateKey(n=n, d=d)
