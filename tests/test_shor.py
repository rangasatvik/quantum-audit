"""Tests for quantum_audit/shor.py: the SWAP multipliers, the classical post-processing, and a full run."""

import pytest
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from quantum_audit.shor import (
    bitstring_to_phase,
    build_shor_circuit,
    factors_from_period,
    find_factors,
    m2mod15,
    m4mod15,
    phase_to_period,
    run_shor,
)


def apply_to_basis_state(gate, y: int) -> int:
    """Put 4 qubits in the state |y>, apply the gate, and read back the (single) result."""
    qc = QuantumCircuit(4)
    for bit in range(4):
        if (y >> bit) & 1:
            qc.x(bit)
    qc.append(gate, range(4))
    # Exact simulation: the result is one basis state with probability 1.
    probabilities = Statevector(qc).probabilities_dict()
    assert len(probabilities) == 1
    (bitstring,) = probabilities
    return int(bitstring, 2)


# --- The SWAP-built multipliers ----------------------------------------------------


@pytest.mark.parametrize("y", range(1, 15))
def test_m2mod15_multiplies_by_2(y):
    assert apply_to_basis_state(m2mod15(), y) == (2 * y) % 15


@pytest.mark.parametrize("y", range(1, 15))
def test_m4mod15_multiplies_by_4(y):
    assert apply_to_basis_state(m4mod15(), y) == (4 * y) % 15


def test_circuit_shape():
    qc = build_shor_circuit()
    assert qc.num_qubits == 12  # 8 counting + 4 work
    assert qc.num_clbits == 8  # only the counting qubits are measured


def test_unsupported_base_is_rejected():
    # 7^1 mod 15 = 7, and there is no SWAP-only gate for "multiply by 7" in this module.
    with pytest.raises(ValueError):
        build_shor_circuit(a=7)


# --- Post-processing: bitstring -> phase -> period -> factors ----------------------


@pytest.mark.parametrize(
    "bitstring, phase",
    [("00000000", 0.0), ("01000000", 0.25), ("10000000", 0.5), ("11000000", 0.75)],
)
def test_bitstring_to_phase(bitstring, phase):
    assert bitstring_to_phase(bitstring) == phase


@pytest.mark.parametrize("phase, r", [(0.25, 4), (0.75, 4), (0.5, 2), (0.0, 1)])
def test_phase_to_period(phase, r):
    assert phase_to_period(phase, 15) == r


def test_continued_fractions_handle_imprecise_phases():
    # A noisy phase near 1/4 (e.g. 65/256 instead of 64/256) still rounds to r = 4.
    assert phase_to_period(65 / 256, 15) == 4


def test_period_4_gives_3_and_5():
    # 2^(4/2) = 4. gcd(4 - 1, 15) = 3 and gcd(4 + 1, 15) = 5.
    assert factors_from_period(2, 4, 15) == {3, 5}


@pytest.mark.parametrize("r", [1, 2, 3])
def test_wrong_periods_are_rejected(r):
    # None of these satisfy 2^r mod 15 = 1, so they are not the period.
    assert factors_from_period(2, r, 15) is None


def test_odd_period_is_rejected():
    # 2 has period 3 mod 7 (2, 4, 1, ...). r/2 isn't a whole number, so the trick fails.
    assert factors_from_period(2, 3, 7) is None


def test_trivial_minus_one_case_is_rejected():
    # 14 = -1 (mod 15), so 14 has period 2, but 14^(2/2) = -1 gives only 1 and 15.
    assert factors_from_period(14, 2, 15) is None


def test_another_base_works():
    # 4 has period 2 mod 15 (4, 1, ...): gcd(4 - 1, 15) = 3, gcd(4 + 1, 15) = 5.
    assert factors_from_period(4, 2, 15) == {3, 5}


def test_find_factors_skips_unlucky_outcomes():
    # The most frequent outcomes here are phase 0 and phase 0.5, which don't work.
    # find_factors must move on and succeed with phase 0.25.
    counts = {"00000000": 300, "10000000": 280, "01000000": 250, "11000000": 194}
    result = find_factors(counts, a=2, n=15)
    assert result.factors == {3, 5}
    assert result.phase == 0.25
    assert result.period == 4


def test_find_factors_reports_failure():
    # Only unlucky outcomes: no factors can be found.
    result = find_factors({"00000000": 512, "10000000": 512}, a=2, n=15)
    assert result.factors is None


# --- Full run on the simulator -----------------------------------------------------


def test_full_run_factors_15():
    result = run_shor(a=2, shots=1024, seed=42)
    assert result.factors == {3, 5}
    assert result.period == 4


def test_full_run_only_measures_the_four_expected_phases():
    # With r = 4 the ideal circuit can only output k/4 for k = 0, 1, 2, 3.
    result = run_shor(a=2, shots=1024, seed=42)
    phases = {bitstring_to_phase(b) for b in result.counts}
    assert phases == {0.0, 0.25, 0.5, 0.75}
    assert sum(result.counts.values()) == 1024
