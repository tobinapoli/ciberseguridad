import sys
import math
import os
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from qiskit.qpy import load
from qiskit.circuit.library import MCXGate

script_dir = os.path.dirname(os.path.abspath(__file__))
oracle_path = os.path.join(script_dir, 'oracle.qpy')

try:
  with open(oracle_path, 'rb') as f:
    circ = load(f)[0]
except FileNotFoundError:
  print(f"Error: 'oracle.qpy' not found at {oracle_path}")
  sys.exit(1)

n = circ.num_qubits
print(f"[*] Número de qubits: {n}")

circ_decomposed = transpile(circ, basis_gates=['u', 'cx', 'id'])
oracle_gate = circ_decomposed.to_gate(label='Oracle')

# Calcular iteraciones óptimas de Grover
# Fórmula: π/4 * √N donde N = 2^n
N = 2 ** n
optimal_iterations = (math.pi / 4) * math.sqrt(N)
iterations = int(math.floor(optimal_iterations))

print(f"[*] Espacio de búsqueda (N): {N}")
print(f"[*] Iteraciones óptimas (π/4 * √N): {optimal_iterations}")
print(f"[*] Iteraciones a usar (floor): {iterations}")

qc = QuantumCircuit(n, n)
qc.h(list(range(n)))

# Aplicar Grover con número óptimo de iteraciones
for iteration in range(iterations):
  qc.append(oracle_gate, list(range(n)))

  qc.h(list(range(n)))
  qc.x(list(range(n)))

  qc.h(n - 1)

  mcx_gate = MCXGate(n - 1)
  qc.append(mcx_gate, list(range(n)))

  qc.h(n - 1)

  qc.x(list(range(n)))
  qc.h(list(range(n)))

qc.measure(list(range(n)), list(range(n)))

backend = Aer.get_backend('qasm_simulator')
qc_transpiled = transpile(qc, backend)
job = backend.run(qc_transpiled, shots=2048)
result = job.result()
counts = result.get_counts()

print(f"\n[*] Resultados de mediciones:")
print(counts)

# Encontrar el resultado más probable (el "secret")
most_common = max(counts, key=counts.get)
secret_str = most_common
secret_int = int(secret_str, 2)  # Convertir de binario a decimal

print(f"\n[+] Resultado más probable (secret): {secret_str} (decimal: {secret_int})")
print(f"[+] Iteraciones óptimas (floor): {iterations}")

# Calcular flag: secret × floor(iteraciones)
flag_value = secret_int * iterations

print(f"\n[+] Cálculo: {secret_int} × {iterations} = {flag_value}")
print(f"\n[+] FLAG: UNLP{{{flag_value}}}")
