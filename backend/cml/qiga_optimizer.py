"""
ICDS-H Quantum-Inspired Genetic Algorithm (QIGA) Optimizer
===========================================================
Selects the optimal response strategy combination for a given
threat scenario by minimizing:

    F = α·Downtime + β·DataLoss + γ·RecoveryCost

Subject to:
    - Resource capacity constraints
    - Security policy constraints
    - Risk severity thresholds

Quantum-inspired mechanism: Each chromosome gene is represented as a
quantum bit (Q-bit) with probability amplitudes [α, β] where α² + β² = 1.
The population evolves via rotation gates that update amplitudes toward
better solutions — simulating quantum superposition exploration.
"""
import numpy as np
import random
from typing import List, Dict, Tuple, Optional

# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE ACTION LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
RESPONSE_ACTIONS = [
    {
        "id": "ISOLATE",
        "name": "Isolate Device",
        "cost": 1,
        "downtime": 0.6,
        "data_loss": 0.2,
        "recovery_time": 15,
        "effectiveness": 0.75,
        "resource_units": 2,
        "applicable_attacks": [
            "Ransomware", "Insider Threat", "DDoS", "DoS",
            "Backdoor", "MITM", "Anomaly (Zero-Day)",
        ],
        "policy_min_severity": "MEDIUM",
    },
    {
        "id": "BLOCK",
        "name": "Block Traffic",
        "cost": 2,
        "downtime": 0.3,
        "data_loss": 0.1,
        "recovery_time": 5,
        "effectiveness": 0.85,
        "resource_units": 1,
        "applicable_attacks": [
            "DDoS", "DoS", "Phishing", "Scanning", "XSS",
            "Injection", "MITM", "Anomaly (Zero-Day)",
        ],
        "policy_min_severity": "LOW",
    },
    {
        "id": "RESTORE",
        "name": "Restore Backup",
        "cost": 3,
        "downtime": 0.8,
        "data_loss": 0.05,
        "recovery_time": 120,
        "effectiveness": 0.95,
        "resource_units": 4,
        "applicable_attacks": ["Ransomware", "Backdoor"],
        "policy_min_severity": "HIGH",
    },
    {
        "id": "RESET",
        "name": "Reset Account / Credentials",
        "cost": 1,
        "downtime": 0.15,
        "data_loss": 0.05,
        "recovery_time": 10,
        "effectiveness": 0.70,
        "resource_units": 1,
        "applicable_attacks": [
            "Insider Threat", "Phishing", "Password Attack",
        ],
        "policy_min_severity": "LOW",
    },
    {
        "id": "PATCH",
        "name": "Apply Security Patch",
        "cost": 2,
        "downtime": 0.25,
        "data_loss": 0.02,
        "recovery_time": 20,
        "effectiveness": 0.82,
        "resource_units": 2,
        "applicable_attacks": [
            "Phishing", "Ransomware", "XSS", "Injection",
            "Backdoor",
        ],
        "policy_min_severity": "MEDIUM",
    },
    {
        "id": "WAF_RULE",
        "name": "Deploy WAF Rule",
        "cost": 1,
        "downtime": 0.05,
        "data_loss": 0.01,
        "recovery_time": 3,
        "effectiveness": 0.78,
        "resource_units": 1,
        "applicable_attacks": [
            "XSS", "Injection", "Scanning", "Phishing",
        ],
        "policy_min_severity": "LOW",
    },
    {
        "id": "MONITOR_ENHANCED",
        "name": "Enhanced Monitoring",
        "cost": 1,
        "downtime": 0.0,
        "data_loss": 0.0,
        "recovery_time": 0,
        "effectiveness": 0.55,
        "resource_units": 1,
        "applicable_attacks": [
            "Scanning", "MITM", "Password Attack",
            "Insider Threat", "Anomaly (Zero-Day)",
        ],
        "policy_min_severity": "LOW",
    },
]

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
MAX_RESOURCES = 6   # Maximum resource units available simultaneously


# ─────────────────────────────────────────────────────────────────────────────
# OBJECTIVE FUNCTION
# ─────────────────────────────────────────────────────────────────────────────
def objective_function(
    chromosome: List[int],
    actions: List[Dict],
    risk_score: float,
    alpha: float = 0.4,  # weight: downtime
    beta: float = 0.35,  # weight: data loss
    gamma: float = 0.25, # weight: recovery cost
) -> Tuple[float, bool]:
    """
    Evaluates a chromosome (combination of selected actions).
    Returns (fitness_score, is_feasible).
    Lower is better (minimization problem).
    """
    selected = [actions[i] for i, bit in enumerate(chromosome) if bit == 1]

    if not selected:
        return 999.0, False  # Penalty for no action

    # Constraint 1: Resource capacity
    total_resources = sum(a["resource_units"] for a in selected)
    if total_resources > MAX_RESOURCES:
        return 999.0 + total_resources, False

    # Aggregate metrics (combined effect — complementary actions reduce overall impact)
    n = len(selected)
    combined_downtime = 1 - np.prod([1 - a["downtime"] for a in selected]) / n
    combined_data_loss = 1 - np.prod([1 - a["data_loss"] for a in selected]) / n
    combined_effectiveness = 1 - np.prod([1 - a["effectiveness"] for a in selected])
    combined_cost = sum(a["cost"] for a in selected) / (3 * len(actions))

    # Effectiveness bonus: high effectiveness reduces F
    effectiveness_bonus = combined_effectiveness * 0.4

    # Risk severity multiplier
    risk_mult = risk_score / 100.0

    F = (alpha * combined_downtime + beta * combined_data_loss + gamma * combined_cost) * risk_mult
    F = F - effectiveness_bonus
    F = max(0, F)  # Cannot be negative
    return round(F, 6), True


# ─────────────────────────────────────────────────────────────────────────────
# QUANTUM-INSPIRED GENETIC ALGORITHM
# ─────────────────────────────────────────────────────────────────────────────
class QIGAOptimizer:
    """
    Quantum-Inspired Genetic Algorithm for cyber response optimization.

    Each individual is a Q-bit chromosome where each gene [α_i, β_i]
    represents the probability amplitude for including action i.
    Observation collapses the Q-chromosome to a binary string.
    Rotation gates update amplitudes toward the best-known solution.
    """

    def __init__(
        self,
        n_qubits: int = 7,
        population_size: int = 20,
        n_generations: int = 40,
        rotation_angle: float = 0.05 * np.pi,
        mutation_rate: float = 0.10,
    ):
        self.n_qubits = n_qubits
        self.pop_size = population_size
        self.n_gen = n_generations
        self.theta = rotation_angle
        self.mutation_rate = mutation_rate

    def _init_population(self) -> np.ndarray:
        """Initialize Q-bit population with equal superposition (π/4 angles)."""
        # Shape: [pop_size, n_qubits, 2] where last dim = [alpha, beta]
        pop = np.full((self.pop_size, self.n_qubits, 2), 1.0 / np.sqrt(2))
        return pop

    def _observe(self, q_individual: np.ndarray) -> List[int]:
        """Collapse Q-bit individual to binary chromosome via measurement."""
        chromosome = []
        for gene in q_individual:
            alpha, beta = gene
            prob_1 = beta ** 2  # Probability of selecting action
            chromosome.append(1 if random.random() < prob_1 else 0)
        return chromosome

    def _rotate_gate(
        self,
        q_individual: np.ndarray,
        chromosome: List[int],
        best_chromosome: List[int],
        fitness: float,
        best_fitness: float,
    ) -> np.ndarray:
        """Apply quantum rotation gate to update Q-bit amplitudes."""
        new_individual = q_individual.copy()
        for i in range(self.n_qubits):
            xi = chromosome[i]
            bi = best_chromosome[i]

            # Determine rotation direction
            if xi == 0 and bi == 1 and fitness > best_fitness:
                sign = 1  # rotate toward bi=1
            elif xi == 1 and bi == 0 and fitness > best_fitness:
                sign = -1
            elif xi == 0 and bi == 0:
                sign = 0
            else:
                sign = 1 if xi == bi else -1

            angle = sign * self.theta
            alpha, beta = q_individual[i]
            cos_a, sin_a = np.cos(angle), np.sin(angle)
            new_individual[i][0] = cos_a * alpha - sin_a * beta
            new_individual[i][1] = sin_a * alpha + cos_a * beta

            # Normalize
            norm = np.sqrt(new_individual[i][0]**2 + new_individual[i][1]**2)
            if norm > 0:
                new_individual[i] /= norm

        return new_individual

    def _mutate(self, chromosome: List[int]) -> List[int]:
        """Apply bit-flip mutation with given rate."""
        return [1 - bit if random.random() < self.mutation_rate else bit
                for bit in chromosome]

    def optimize(
        self,
        risk_score: float,
        attack_type: str,
        severity: str,
        alpha: float = 0.4,
        beta: float = 0.35,
        gamma: float = 0.25,
    ) -> Dict:
        """
        Run QIGA and return the optimal response strategy.

        Returns dict with:
            - best_actions: list of selected response actions
            - objective_score: minimized F value
            - convergence: list of best F per generation
            - all_actions: full scored action table
            - weights: (alpha, beta, gamma)
        """
        valid_attacks = {
            "DDoS", "DoS", "Ransomware", "Backdoor", "Injection",
            "Password Attack", "Scanning", "XSS", "MITM",
            "Phishing", "Insider Threat", "Anomaly (Zero-Day)",
        }
        if attack_type not in valid_attacks:
            raise ValueError(f"QIGA optimization is not supported for attack type: {attack_type}")

        # Filter actions by policy (min severity)
        sev_level = SEVERITY_ORDER.get(severity, 1)
        candidate_actions = [
            a for a in RESPONSE_ACTIONS
            if SEVERITY_ORDER.get(a["policy_min_severity"], 0) <= sev_level
        ]
        n = len(candidate_actions)
        if n == 0:
            candidate_actions = RESPONSE_ACTIONS[:3]
            n = 3

        # Re-initialize with correct number of qubits
        self.n_qubits = n

        # Initialize Q-population
        q_population = self._init_population()

        best_chromosome = [0] * n
        best_fitness = float("inf")
        convergence = []

        for gen in range(self.n_gen):
            # Observe all individuals
            chromosomes = [self._observe(q_population[i]) for i in range(self.pop_size)]

            # Mutate
            chromosomes = [self._mutate(c) for c in chromosomes]

            # Evaluate
            fitnesses = []
            for c in chromosomes:
                f, feasible = objective_function(c, candidate_actions, risk_score, alpha, beta, gamma)
                fitnesses.append(f)

            # Find generation best
            gen_best_idx = int(np.argmin(fitnesses))
            gen_best_f = fitnesses[gen_best_idx]

            if gen_best_f < best_fitness:
                best_fitness = gen_best_f
                best_chromosome = chromosomes[gen_best_idx]

            convergence.append(round(best_fitness, 4))

            # Update Q-population via rotation gates
            for i in range(self.pop_size):
                q_population[i] = self._rotate_gate(
                    q_population[i], chromosomes[i],
                    best_chromosome, fitnesses[i], best_fitness
                )

        # Build result
        selected_actions = [
            candidate_actions[i] for i, bit in enumerate(best_chromosome) if bit == 1
        ]
        if not selected_actions:
            # Fallback: take highest effectiveness action
            selected_actions = [max(candidate_actions, key=lambda a: a["effectiveness"])]

        # Score all actions for display
        all_scored = []
        for a in RESPONSE_ACTIONS:
            c = [1 if x["id"] == a["id"] else 0 for x in candidate_actions]
            f, feasible = objective_function(c, candidate_actions, risk_score, alpha, beta, gamma)
            all_scored.append({
                **a,
                "objective_score": round(f, 4),
                "selected": a["id"] in [s["id"] for s in selected_actions],
                "feasible": feasible,
            })

        return {
            "best_actions": selected_actions,
            "objective_score": round(best_fitness, 4),
            "convergence": convergence,
            "all_actions": all_scored,
            "weights": {"alpha": alpha, "beta": beta, "gamma": gamma},
            "generations": self.n_gen,
            "population_size": self.pop_size,
            "attack_type": attack_type,
            "severity": severity,
            "risk_score": risk_score,
            "combined_effectiveness": round(
                1 - np.prod([1 - a["effectiveness"] for a in selected_actions]), 3
            ) if selected_actions else 0,
            "combined_cost": sum(a["cost"] for a in selected_actions),
            "total_downtime_min": sum(a["recovery_time"] for a in selected_actions),
        }


# Singleton instance
qiga = QIGAOptimizer(population_size=20, n_generations=40)
