"""
Shor's algorithm for N = 15, following IBM's tutorial:
https://quantum.cloud.ibm.com/docs/en/tutorials/shors-algorithm

The goal: find the factors of N (here 3 and 5). Shor's does this by finding the PERIOD r
of the function f(x) = a^x mod N, then using r to compute the factors with gcd.

For a = 2 and N = 15:
    x:          0  1  2  3  4  5  6  7 ...
    2^x mod 15: 1  2  4  8  1  2  4  8 ...   -> repeats every 4 steps, so r = 4.

The algorithm has two halves:
  QUANTUM (finds r):
    1. Put 8 "counting" qubits into superposition with Hadamard gates, so they hold
       every x from 0 to 255 at once.
    2. Use them to control "multiply by a mod N" gates on 4 "work" qubits. The work
       register ends up holding a^x mod N, linked (entangled) with each x.
    3. Apply the inverse Quantum Fourier Transform (QFT) to the counting qubits. This
       turns the repeating pattern into sharp peaks at multiples of 1/r.
    4. Measure. Each result is a number k/r ("phase") written as an 8-bit fraction.
  CLASSICAL (turns r into factors):
    5. Phase -> fraction with continued fractions -> denominator is r.
    6. gcd(a^(r/2) - 1, N) and gcd(a^(r/2) + 1, N) are factors of N.

Honest limits: the multiplier gates below are hand-built for N = 15 only. They are cheap
because multiplying by 2 mod 15 happens to be a simple bit rotation. Real RSA numbers
need general modular multiplication circuits that are vastly larger (see the README).
"""

from dataclasses import dataclass
from fractions import Fraction
from math import gcd

from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister, transpile
from qiskit.circuit import Gate
from qiskit.circuit.library import QFTGate
from qiskit_aer import AerSimulator

N = 15  # the number to factor
A = 2  # the base "a" in a^x mod N (IBM's tutorial uses 2)
N_COUNT = 8  # counting qubits: measure the phase to 8 bits of precision
N_WORK = 4  # work qubits: enough to hold numbers 0..15
SHOTS = 1024


# --- Step 2's building blocks: "multiply by 2^s mod 15" made from SWAP gates ----------
#
# Why SWAPs work: write a number y as 4 bits (y3 y2 y1 y0). Multiplying by 2 shifts the
# bits left. Normally the top bit would fall off as 16, but 16 mod 15 = 1, so it wraps
# around to the bottom. Multiplying by 2 mod 15 is therefore just a bit ROTATION, and
# rotations can be done by swapping qubits. No arithmetic gates needed.
#
# Example: y = 3 = 0011  ->  rotate left  ->  0110 = 6 = 2 * 3.   (y = 0 and y = 15 are
# never reached here, because the work register starts at 1 and stays in 1..14.)


def m2mod15() -> Gate:
    """Gate that maps |y> to |2y mod 15> on 4 qubits (qubit 0 = lowest bit)."""
    u = QuantumCircuit(N_WORK)
    # Three swaps bubble the top bit (qubit 3) down to qubit 0 and shift the others up.
    u.swap(2, 3)
    u.swap(1, 2)
    u.swap(0, 1)
    gate = u.to_gate()
    gate.name = "M_2"
    return gate


def m4mod15() -> Gate:
    """Gate that maps |y> to |4y mod 15> on 4 qubits: a rotation by 2 bits."""
    u = QuantumCircuit(N_WORK)
    u.swap(1, 3)
    u.swap(0, 2)
    gate = u.to_gate()
    gate.name = "M_4"
    return gate


# Which gate multiplies by a given number mod 15. Multiplying by 1 does nothing (identity),
# so we skip it entirely. This is one reason the N = 15 circuit is so shallow.
MULTIPLIERS = {1: None, 2: m2mod15, 4: m4mod15}


def build_shor_circuit(a: int = A) -> QuantumCircuit:
    """Build the period-finding circuit for a^x mod 15: 8 counting qubits + 4 work qubits."""
    control = QuantumRegister(N_COUNT, name="C")  # counting qubits (they hold x)
    target = QuantumRegister(N_WORK, name="T")  # work qubits (they hold a^x mod 15)
    output = ClassicalRegister(N_COUNT, name="out")  # where the measurements go
    circuit = QuantumCircuit(control, target, output)

    # Step 1a: work register starts at |1>, since a^0 = 1.
    circuit.x(target[0])

    # Step 1b: Hadamard on every counting qubit -> equal superposition of x = 0..255.
    for qubit in control:
        circuit.h(qubit)

    # Step 2: controlled multiplications.
    # Counting qubit k stands for the "2^k" place of x. If it is 1, multiply the work
    # register by a^(2^k) mod N. Doing this for every k multiplies by a^x in total.
    for k, qubit in enumerate(control):
        # Compute a^(2^k) mod N classically (cheap, even for huge numbers).
        b = pow(a, 2**k, N)
        if b not in MULTIPLIERS:
            raise ValueError(f"No SWAP-based gate for multiplying by {b} mod {N}; use a = 2")
        make_gate = MULTIPLIERS[b]
        if make_gate is None:
            continue  # multiply by 1: nothing to do
        # .control() turns the gate into "do this only if the control qubit is 1".
        circuit.append(make_gate().control(), [qubit] + list(target))

    # Step 3: inverse QFT on the counting qubits turns the period into measurable peaks.
    circuit.append(QFTGate(N_COUNT).inverse(), control)

    # Step 4: measure only the counting qubits. (The work qubits are not needed.)
    circuit.measure(control, output)
    return circuit


# --- Classical post-processing (steps 5 and 6) --------------------------------------


def bitstring_to_phase(bitstring: str) -> float:
    """Turn a measured bitstring into a phase between 0 and 1.

    The counting register holds an 8-bit number k. The phase is k / 2^8.
    Example: "01000000" = 64, and 64 / 256 = 0.25.
    """
    return int(bitstring, 2) / 2 ** len(bitstring)


def phase_to_period(phase: float, n: int = N) -> int:
    """Guess the period r from a phase, using continued fractions.

    The phase should be close to some fraction s/r. Fraction.limit_denominator finds the
    closest fraction whose denominator is at most n (the period can't be bigger than N).
    Example: 0.25 -> 1/4 -> r = 4.   0.75 -> 3/4 -> r = 4.   0.5 -> 1/2 -> r = 2.
    """
    return Fraction(phase).limit_denominator(n).denominator


def factors_from_period(a: int, r: int, n: int = N) -> set[int] | None:
    """Use the period r to find factors of n. Returns None if this r doesn't work.

    The idea: if a^r = 1 (mod n) and r is even, then
        a^r - 1 = (a^(r/2) - 1) * (a^(r/2) + 1)  is a multiple of n,
    so n shares factors with those two brackets, and gcd finds them.
    """
    # The guess must really be a period. A phase of 0.5 gives r = 2, but 2^2 mod 15 = 4,
    # not 1, so r = 2 is wrong and we skip it.
    if pow(a, r, n) != 1:
        return None
    # The trick needs r/2 to be a whole number.
    if r % 2 != 0:
        return None
    half = pow(a, r // 2, n)
    # If a^(r/2) = -1 (mod n), the brackets give only the trivial factors 1 and n.
    if half == n - 1:
        return None
    candidates = {gcd(half - 1, n), gcd(half + 1, n)}
    # Keep only real factors (not 1 and not n itself).
    factors = {f for f in candidates if 1 < f < n}
    if not factors:
        return None
    # If we found one factor f, the other is n // f.
    f = factors.pop()
    return {f, n // f}


@dataclass
class ShorResult:
    """What a run of Shor's found, kept together so it can be printed or tested."""

    factors: set[int] | None  # e.g. {3, 5}, or None if no outcome worked
    period: int | None  # the period r that gave the factors
    phase: float | None  # the measured phase that gave r
    counts: dict[str, int]  # raw measurement counts, e.g. {"01000000": 260, ...}


def find_factors(counts: dict[str, int], a: int = A, n: int = N) -> ShorResult:
    """Try measured outcomes from most to least frequent until one gives the factors."""
    for bitstring, _ in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        phase = bitstring_to_phase(bitstring)
        r = phase_to_period(phase, n)
        factors = factors_from_period(a, r, n)
        if factors:
            return ShorResult(factors=factors, period=r, phase=phase, counts=counts)
        # Otherwise this outcome was unlucky (e.g. phase 0 or 0.5); try the next one.
    return ShorResult(factors=None, period=None, phase=None, counts=counts)


def phase_counts(counts: dict[str, int]) -> dict[str, int]:
    """Relabel counts by phase ("0.25") instead of bitstring ("01000000"), for plotting."""
    return {f"{bitstring_to_phase(b):.4g}": c for b, c in counts.items()}


def run_shor(a: int = A, shots: int = SHOTS, seed: int | None = None) -> ShorResult:
    """Build the circuit, run it on the Aer simulator, and post-process the results."""
    # Lucky shortcut: if a already shares a factor with N, no quantum step is needed.
    # (Not the case for a = 2 and N = 15, but this check is part of the full algorithm.)
    shared = gcd(a, N)
    if shared > 1:
        return ShorResult(factors={shared, N // shared}, period=None, phase=None, counts={})

    circuit = build_shor_circuit(a)
    simulator = AerSimulator()
    compiled = transpile(circuit, simulator)
    counts = simulator.run(compiled, shots=shots, seed_simulator=seed).result().get_counts()
    return find_factors(counts, a, N)


def main() -> None:
    """Run Shor's for N = 15, print what happened, and save a phase histogram."""
    from pathlib import Path

    import matplotlib

    matplotlib.use("Agg")  # draw to a file instead of opening a window
    from qiskit.visualization import plot_histogram

    circuit = build_shor_circuit(A)
    print(f"Factoring N = {N} with a = {A}: {N_COUNT} counting + {N_WORK} work qubits")
    print(circuit.draw(output="text", fold=-1))

    result = run_shor(A, shots=SHOTS, seed=42)

    print(f"\nMeasured phases from {SHOTS} shots:")
    print("  bitstring   phase  fraction  r guess  count")
    for bitstring, count in sorted(result.counts.items()):
        phase = bitstring_to_phase(bitstring)
        frac = Fraction(phase).limit_denominator(N)
        print(f"  {bitstring}  {phase:5.3f}  {str(frac):>8}  {frac.denominator:>7}  {count:5d}")

    if result.factors:
        p, q = sorted(result.factors)
        print(f"\nPhase {result.phase} -> period r = {result.period}")
        print(f"{A}^({result.period}/2) mod {N} = {pow(A, result.period // 2, N)}")
        print(f"Factors found: {N} = {p} x {q}")
    else:
        print("\nNo outcome gave the factors. Try running again.")

    out_path = Path(__file__).resolve().parent.parent / "docs" / "shor_phases.png"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig = plot_histogram(
        phase_counts(result.counts),
        title=f"Shor's algorithm, N = {N}, a = {A}: measured phases ({SHOTS} shots)",
    )
    fig.axes[0].set_xlabel("Measured phase (k / r)")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Histogram saved to {out_path}")


if __name__ == "__main__":
    main()
