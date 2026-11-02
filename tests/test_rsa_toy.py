"""Tests for quantum_audit/rsa_toy.py, using the two toy keys from PLAN.md: N = 15 and N = 21."""

import pytest

from quantum_audit.rsa_toy import (
    PrivateKey,
    PublicKey,
    decrypt,
    encrypt,
    generate_keypair,
    is_prime,
    rebuild_private_key,
)

# (p, q) pairs used throughout. N = 15 and N = 21 are the numbers Shor's will factor later.
TOY_PRIMES = [(3, 5), (3, 7)]


# --- Key generation -----------------------------------------------------------


def test_keypair_for_n15():
    # phi = 2 * 4 = 8. Smallest e > 1 with no factor in common with 8 is 3.
    # 3 * 3 = 9 = 1 (mod 8), so d = 3.
    public, private = generate_keypair(3, 5)
    assert public == PublicKey(n=15, e=3)
    assert private == PrivateKey(n=15, d=3)


def test_keypair_for_n21():
    # phi = 2 * 6 = 12. e = 2, 3, 4 all share a factor with 12, so e = 5.
    # 5 * 5 = 25 = 1 (mod 12), so d = 5.
    public, private = generate_keypair(3, 7)
    assert public == PublicKey(n=21, e=5)
    assert private == PrivateKey(n=21, d=5)


@pytest.mark.parametrize("p, q", TOY_PRIMES)
def test_e_times_d_is_1_mod_phi(p, q):
    # This is the defining property of an RSA key pair.
    public, private = generate_keypair(p, q)
    phi = (p - 1) * (q - 1)
    assert (public.e * private.d) % phi == 1


def test_custom_e_is_used():
    public, private = generate_keypair(3, 7, e=11)
    assert public.e == 11
    assert (11 * private.d) % 12 == 1


# --- Encryption and decryption ------------------------------------------------


def test_known_ciphertexts():
    # Worked by hand: 2^3 = 8, and 8 mod 15 = 8.
    public15, _ = generate_keypair(3, 5)
    assert encrypt(2, public15) == 8
    # 2^5 = 32, and 32 mod 21 = 11.
    public21, _ = generate_keypair(3, 7)
    assert encrypt(2, public21) == 11


@pytest.mark.parametrize("p, q", TOY_PRIMES)
def test_every_message_round_trips(p, q):
    # N is tiny, so we can check every possible message from 0 to N - 1.
    public, private = generate_keypair(p, q)
    for message in range(public.n):
        assert decrypt(encrypt(message, public), private) == message


# --- Rebuilding the private key from the factors ------------------------------


@pytest.mark.parametrize("p, q", TOY_PRIMES)
def test_rebuild_matches_original(p, q):
    # An attacker who only has the public key and the factors gets the exact same d.
    public, private = generate_keypair(p, q)
    assert rebuild_private_key(public.n, public.e, p, q) == private


@pytest.mark.parametrize("p, q", TOY_PRIMES)
def test_rebuilt_key_decrypts(p, q):
    public, _ = generate_keypair(p, q)
    stolen = rebuild_private_key(public.n, public.e, p, q)
    ciphertext = encrypt(4, public)
    assert decrypt(ciphertext, stolen) == 4


def test_rebuild_order_of_factors_does_not_matter():
    assert rebuild_private_key(15, 3, 5, 3) == rebuild_private_key(15, 3, 3, 5)


def test_rebuild_rejects_wrong_factors():
    with pytest.raises(ValueError):
        rebuild_private_key(21, 5, 3, 5)  # 3 * 5 = 15, not 21


# --- Input checks -------------------------------------------------------------


def test_is_prime():
    assert [k for k in range(20) if is_prime(k)] == [2, 3, 5, 7, 11, 13, 17, 19]


@pytest.mark.parametrize("p, q", [(4, 5), (3, 9), (1, 7), (5, 5)])
def test_rejects_bad_primes(p, q):
    with pytest.raises(ValueError):
        generate_keypair(p, q)


def test_rejects_e_sharing_a_factor_with_phi():
    with pytest.raises(ValueError):
        generate_keypair(3, 7, e=3)  # phi = 12, and 3 divides 12


@pytest.mark.parametrize("message", [-1, 15, 100])
def test_rejects_message_outside_range(message):
    public, _ = generate_keypair(3, 5)
    with pytest.raises(ValueError):
        encrypt(message, public)
