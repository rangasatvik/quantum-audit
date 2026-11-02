"""
Experiment 01: the Bell state.

A Bell state is the simplest example of *entanglement*: two qubits whose
measurement results are perfectly linked, even though each one on its own
looks completely random.

What this script does:
  1. Builds a 2-qubit circuit:  H on qubit 0, then CNOT (qubit 0 -> qubit 1).
  2. Measures both qubits.
  3. Runs the circuit 1,000 times ("shots") on the Aer simulator.
  4. Prints the counts and saves a histogram to docs/bell_state.png.

Expected result: about 50% "00" and 50% "11", and never "01" or "10".

Run it from the project root:
    python experiments/01_bell_state.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # draw to a file instead of opening a window

from qiskit import QuantumCircuit, transpile
from qiskit.visualization import plot_histogram
from qiskit_aer import AerSimulator

SHOTS = 1000
# A fixed seed makes the simulator give the same "random" results every run,
# so the saved histogram matches what you see when you re-run the script.
SEED = 42

# docs/ lives next to experiments/, one level up from this file.
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "docs" / "bell_state.png"


def build_bell_circuit() -> QuantumCircuit:
    """Return a circuit that prepares the Bell state (|00> + |11>) / sqrt(2) and measures it."""
    # 2 qubits (the quantum part) and 2 classical bits (where measurements are stored).
    qc = QuantumCircuit(2, 2)

    # Both qubits start in |0>.
    # Hadamard on qubit 0 puts it in an equal superposition: (|0> + |1>) / sqrt(2).
    qc.h(0)

    # CNOT flips qubit 1 only when qubit 0 is |1>.
    # Applied to the superposition, this gives (|00> + |11>) / sqrt(2):
    # the two qubits are now entangled.
    qc.cx(0, 1)

    # Measure qubit 0 into classical bit 0, and qubit 1 into classical bit 1.
    qc.measure([0, 1], [0, 1])
    return qc


def main() -> None:
    qc = build_bell_circuit()
    print("Circuit:")
    print(qc.draw(output="text"))

    # The Aer simulator runs the circuit on your laptop, with no noise.
    simulator = AerSimulator()

    # transpile() rewrites the circuit into the gates the simulator understands.
    # (For this tiny circuit it changes nothing, but it is the standard step.)
    compiled = transpile(qc, simulator)

    # Run it SHOTS times. Each shot starts fresh and gives one 2-bit result.
    job = simulator.run(compiled, shots=SHOTS, seed_simulator=SEED)
    counts = job.result().get_counts()

    # Qiskit writes bitstrings with qubit 0 on the RIGHT, e.g. "01" means
    # qubit 1 = 0 and qubit 0 = 1. For a Bell state this doesn't matter,
    # because both bits always agree.
    print(f"\nResults from {SHOTS} shots:")
    for outcome in ["00", "01", "10", "11"]:
        n = counts.get(outcome, 0)
        print(f"  {outcome}: {n:4d}  ({n / SHOTS:.1%})")

    # Draw the histogram and save it for the README.
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fig = plot_histogram(counts, title=f"Bell state, {SHOTS} shots (Aer simulator)")
    fig.savefig(OUTPUT_PATH, dpi=150, bbox_inches="tight")
    print(f"\nHistogram saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
