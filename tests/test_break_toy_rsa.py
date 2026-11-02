"""Tests for the end-to-end demo (demos/break_toy_rsa.py) and the scaling chart."""

import pytest

from demos.break_toy_rsa import attack, run_demo
from demos.scaling_chart import make_scaling_chart
from quantum_audit.rsa_toy import encrypt, generate_keypair


def silent(*_args, **_kwargs):
    """Stand-in for print, so tests don't flood the output."""


def test_demo_recovers_the_original_message():
    result = run_demo(message=7, seed=42, log=silent)
    assert result.recovered == 7
    assert result.factors == (3, 5)
    assert result.period == 4
    assert result.d == 3  # the same d Alice generated


@pytest.mark.parametrize("message", [0, 1, 2, 13, 14])
def test_demo_works_for_other_messages(message):
    assert run_demo(message=message, seed=42, log=silent).recovered == message


def test_attack_uses_only_public_information():
    # Hand the attacker just the public key and the ciphertext; the private key is thrown away.
    public_key, _ = generate_keypair(3, 5)
    ciphertext = encrypt(7, public_key)
    assert attack(public_key, ciphertext, seed=1, log=silent).recovered == 7


def test_attack_rejects_keys_shor_cannot_handle():
    # shor.py's circuit is hand-built for N = 15, so N = 21 must fail loudly, not silently.
    public_key, _ = generate_keypair(3, 7)
    with pytest.raises(ValueError):
        attack(public_key, encrypt(2, public_key), log=silent)


def test_scaling_chart_is_written(tmp_path):
    out = make_scaling_chart(tmp_path / "scaling.png")
    assert out.exists()
    assert out.stat().st_size > 10_000  # a real image, not an empty file
