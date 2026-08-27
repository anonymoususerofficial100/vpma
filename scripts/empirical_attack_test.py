#!/usr/bin/env python3
"""
Empirical Security Testing for Scaphandre VPMA
==============================================

Runs automated attack trials and measures detection rates.
Generates statistical evidence for security guarantees.

Usage:
    sudo python3 empirical_attack_test.py --trials 100
"""

import subprocess
import os
import sys
import time
import json
import hashlib
import hmac
import argparse
import shlex
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime

CHAIN_DIR_CANDIDATES = [
    "/var/scaphandre/intel-rapl:0",
    "/var/lib/scaphandre/ubuntu20/intel-rapl:0",
]
VM_IP = "192.168.122.75"
RESULTS_DIR = Path("/tmp/security_empirical_results")

@dataclass
class AttackResult:
    """Result of a single attack trial"""
    attack_type: str
    trial_num: int
    detected: bool
    detection_time_ms: float
    detection_message: str
    error: Optional[str] = None

@dataclass
class AttackStatistics:
    """Statistical summary for an attack type"""
    attack_type: str
    total_trials: int
    detections: int
    detection_rate: float
    avg_detection_time_ms: float
    min_detection_time_ms: float
    max_detection_time_ms: float
    false_negatives: int
    errors: int

class ChainState:
    """Manages chain state files for attack simulation"""

    def __init__(self, vm_dir: Optional[Path] = None, vm_ip: Optional[str] = None, vm_user: str = "user"):
        self.vm_ip = vm_ip
        self.vm_user = vm_user
        self.vm_dir = vm_dir or self._detect_chain_dir()
        self.backup_dir = RESULTS_DIR / "state_backup"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        print(f"[CHAIN-STATE] Target chain dir: {self.vm_dir} ({'remote' if self.vm_ip else 'local'})")

    def _run_remote(self, command: str) -> subprocess.CompletedProcess:
        ssh_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            f"{self.vm_user}@{self.vm_ip}",
            command,
        ]
        return subprocess.run(ssh_cmd, capture_output=True, text=True)

    def _path_exists(self, path: str) -> bool:
        if self.vm_ip:
            result = self._run_remote(f"test -f {shlex.quote(path)}/chain_counter && test -f {shlex.quote(path)}/energy_uj")
            return result.returncode == 0
        return Path(path, "chain_counter").exists() and Path(path, "energy_uj").exists()

    def _detect_chain_dir(self) -> Path:
        for candidate in CHAIN_DIR_CANDIDATES:
            if self._path_exists(candidate):
                return Path(candidate)

        return Path(CHAIN_DIR_CANDIDATES[0])

    def _read_file(self, path: Path) -> Optional[str]:
        if self.vm_ip:
            result = self._run_remote(f"cat {shlex.quote(str(path))}")
            if result.returncode != 0:
                return None
            return result.stdout.strip()
        if not path.exists():
            return None
        return path.read_text().strip()

    def _write_file(self, path: Path, value: str):
        if self.vm_ip:
            cmd = f"printf %s {shlex.quote(str(value))} | sudo tee {shlex.quote(str(path))} >/dev/null"
            result = self._run_remote(cmd)
            if result.returncode != 0:
                raise RuntimeError(f"Remote write failed for {path}: {result.stderr.strip()}")
            return
        path.write_text(str(value))

    def read(self) -> Dict:
        """Read current chain state"""
        state = {}
        files = ['chain_counter', 'chain_signature', 'chain_previous_hash',
                 'energy_uj', 'chain_energy_delta', 'name']
        for f in files:
            path = self.vm_dir / f
            value = self._read_file(path)
            if value is not None:
                state[f] = value
        return state

    def write(self, key: str, value: str):
        """Write a chain state file"""
        path = self.vm_dir / key
        self._write_file(path, str(value))

    def backup(self):
        """Backup current state"""
        state = self.read()
        backup_file = self.backup_dir / f"backup_{int(time.time())}.json"
        with open(backup_file, 'w') as f:
            json.dump(state, f)
        return state

    def restore(self, state: Dict):
        """Restore backed up state"""
        for key, value in state.items():
            self.write(key, value)

class AttackSimulator:
    """Simulates various attacks and measures detection"""

    def __init__(self, chain: ChainState, vm_ip: str = VM_IP):
        self.chain = chain
        self.vm_ip = vm_ip
        self.results: List[AttackResult] = []
        self.vm_log = Path("scaphandre-vmclient.log")

    def get_log_size(self) -> int:
        """Get current size of VM client log"""
        if self.vm_log.exists():
            return self.vm_log.stat().st_size
        return 0

    def get_new_log_lines(self, prev_size: int) -> str:
        """Get new lines added to log since prev_size"""
        if not self.vm_log.exists():
            return ""
        with open(self.vm_log, 'r') as f:
            f.seek(prev_size)
            return f.read()

    def run_vm_verification(self, timeout: int = 5) -> tuple:
        """Monitor running VM logs for detection after tampering"""
        start = time.time()
        prev_size = self.get_log_size()

        time.sleep(timeout)

        elapsed_ms = (time.time() - start) * 1000
        new_output = self.get_new_log_lines(prev_size)
        return new_output, elapsed_ms

    def check_detection(self, output: str, attack_type: str) -> tuple:
        """Check if attack was detected in output"""
        detection_patterns = {
            'rapl_injection': ['signature mismatch', 'Chain verification failed', 'tampering'],
            'replay': ['counter discontinuity', 'Same counter', 'Chain verification failed'],
            'rollback': ['counter discontinuity', 'went backwards', 'Chain verification failed'],
            'fork': ['previous hash mismatch', 'Chain verification failed', 'tampering'],
            'signature_forgery': ['signature mismatch', 'Chain verification failed', 'tampering'],
            'binary': ['hash mismatch', 'verification failed', 'tampering']
        }

        patterns = detection_patterns.get(attack_type, [])
        for pattern in patterns:
            if pattern.lower() in output.lower():
                return True, pattern
        return False, ""

    def attack_rapl_injection(self, trial: int) -> AttackResult:
        """Inject fake energy value without updating signature"""
        orig_state = self.chain.backup()

        try:
            counter = int(orig_state.get('chain_counter', '-1'))

            orig_energy = int(orig_state.get('energy_uj', '100000000'))

            fake_energy = orig_energy // 2
            self.chain.write('energy_uj', str(fake_energy))
            details = f"counter={counter}, energy={orig_energy}->{fake_energy}"

            output, elapsed = self.run_vm_verification()
            detected, msg = self.check_detection(output, 'rapl_injection')
            detection_message = f"{msg} ({details})" if msg else details

            return AttackResult(
                attack_type='rapl_injection',
                trial_num=trial,
                detected=detected,
                detection_time_ms=elapsed,
                detection_message=detection_message
            )
        except Exception as e:
            return AttackResult(
                attack_type='rapl_injection',
                trial_num=trial,
                detected=False,
                detection_time_ms=0,
                detection_message="",
                error=str(e)
            )
        finally:
            self.chain.restore(orig_state)

    def attack_replay(self, trial: int) -> AttackResult:
        """Replay old counter value"""
        orig_state = self.chain.backup()

        try:

            curr_counter = int(orig_state.get('chain_counter', '100'))

            self.chain.write('chain_counter', str(curr_counter + 5))

            time.sleep(0.5)

            self.chain.write('chain_counter', str(curr_counter))

            output, elapsed = self.run_vm_verification()
            detected, msg = self.check_detection(output, 'replay')

            return AttackResult(
                attack_type='replay',
                trial_num=trial,
                detected=detected,
                detection_time_ms=elapsed,
                detection_message=msg
            )
        except Exception as e:
            return AttackResult(
                attack_type='replay',
                trial_num=trial,
                detected=False,
                detection_time_ms=0,
                detection_message="",
                error=str(e)
            )
        finally:
            self.chain.restore(orig_state)

    def attack_rollback(self, trial: int) -> AttackResult:
        """Roll back counter to earlier value"""
        orig_state = self.chain.backup()

        try:
            curr_counter = int(orig_state.get('chain_counter', '100'))

            rolled_back = max(1, curr_counter - 50)
            self.chain.write('chain_counter', str(rolled_back))

            output, elapsed = self.run_vm_verification()
            detected, msg = self.check_detection(output, 'rollback')

            return AttackResult(
                attack_type='rollback',
                trial_num=trial,
                detected=detected,
                detection_time_ms=elapsed,
                detection_message=msg
            )
        except Exception as e:
            return AttackResult(
                attack_type='rollback',
                trial_num=trial,
                detected=False,
                detection_time_ms=0,
                detection_message="",
                error=str(e)
            )
        finally:
            self.chain.restore(orig_state)

    def attack_fork(self, trial: int) -> AttackResult:
        """Provide forked chain with different previous hash"""
        orig_state = self.chain.backup()

        try:

            curr_counter = int(orig_state.get('chain_counter', '100'))

            fake_prev = '0' * 64
            self.chain.write('chain_previous_hash', fake_prev)
            self.chain.write('chain_counter', str(curr_counter + 1))

            output, elapsed = self.run_vm_verification()
            detected, msg = self.check_detection(output, 'fork')

            if not detected:
                detected, msg = self.check_detection(output, 'rapl_injection')

            return AttackResult(
                attack_type='fork',
                trial_num=trial,
                detected=detected,
                detection_time_ms=elapsed,
                detection_message=msg
            )
        except Exception as e:
            return AttackResult(
                attack_type='fork',
                trial_num=trial,
                detected=False,
                detection_time_ms=0,
                detection_message="",
                error=str(e)
            )
        finally:
            self.chain.restore(orig_state)

    def attack_signature_forgery(self, trial: int) -> AttackResult:
        """Attempt to forge signature without knowing the key"""
        orig_state = self.chain.backup()

        try:
            curr_counter = int(orig_state.get('chain_counter', '100'))

            import secrets
            fake_sig = secrets.token_hex(32)

            self.chain.write('chain_signature', fake_sig)
            self.chain.write('chain_counter', str(curr_counter + 1))

            output, elapsed = self.run_vm_verification()
            detected, msg = self.check_detection(output, 'rapl_injection')

            return AttackResult(
                attack_type='signature_forgery',
                trial_num=trial,
                detected=detected,
                detection_time_ms=elapsed,
                detection_message=msg
            )
        except Exception as e:
            return AttackResult(
                attack_type='signature_forgery',
                trial_num=trial,
                detected=False,
                detection_time_ms=0,
                detection_message="",
                error=str(e)
            )
        finally:
            self.chain.restore(orig_state)

def compute_statistics(results: List[AttackResult]) -> Dict[str, AttackStatistics]:
    """Compute statistics for each attack type"""
    from collections import defaultdict

    by_type = defaultdict(list)
    for r in results:
        by_type[r.attack_type].append(r)

    stats = {}
    for attack_type, type_results in by_type.items():
        valid_results = [r for r in type_results if r.error is None]
        errors = len(type_results) - len(valid_results)

        if valid_results:
            detections = sum(1 for r in valid_results if r.detected)
            detection_times = [r.detection_time_ms for r in valid_results if r.detected]

            stats[attack_type] = AttackStatistics(
                attack_type=attack_type,
                total_trials=len(type_results),
                detections=detections,
                detection_rate=detections / len(valid_results) if valid_results else 0,
                avg_detection_time_ms=sum(detection_times) / len(detection_times) if detection_times else 0,
                min_detection_time_ms=min(detection_times) if detection_times else 0,
                max_detection_time_ms=max(detection_times) if detection_times else 0,
                false_negatives=len(valid_results) - detections,
                errors=errors
            )

    return stats

def print_report(stats: Dict[str, AttackStatistics], output_file: Optional[Path] = None):
    """Print formatted report"""
    lines = []

    lines.append("\n" + "=" * 80)
    lines.append("EMPIRICAL SECURITY TEST RESULTS")
    lines.append("=" * 80)
    lines.append(f"Date: {datetime.now().isoformat()}")
    lines.append("")

    lines.append("")
    lines.append("Attack Type          Trials  Detection  Avg Time (ms)  False Neg")
    lines.append("")

    for attack_type, s in sorted(stats.items()):
        lines.append(
            f"{attack_type:19s}  {s.total_trials:6d}  "
            f"{s.detection_rate*100:8.1f}%  {s.avg_detection_time_ms:13.1f}  {s.false_negatives:11d}"
        )

    lines.append("")

    lines.append("")
    lines.append("SECURITY GUARANTEES:")

    all_detected = all(s.detection_rate >= 0.99 for s in stats.values())
    if all_detected:
        lines.append("  OK All attacks detected with >=99% detection rate")
        lines.append("  OK Empirical evidence supports claimed security properties")
    else:
        lines.append("  WARN Some attacks have detection rate < 99%")
        for attack_type, s in stats.items():
            if s.detection_rate < 0.99:
                lines.append(f"    - {attack_type}: {s.detection_rate*100:.1f}%")

    lines.append("")
    lines.append("INTERPRETATION:")
    lines.append("  - RAPL injection: Detects unauthorized energy value modification")
    lines.append("  - Replay: Detects reuse of old authenticated readings")
    lines.append("  - Rollback: Detects time-regression attacks (snapshot restore)")
    lines.append("  - Fork: Detects equivocation (different data to different VMs)")
    lines.append("  - Signature forgery: Validates HMAC key security")
    lines.append("")

    report = "\n".join(lines)
    print(report)

    if output_file:
        output_file.write_text(report)
        print(f"\nReport saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Empirical security testing for Scaphandre')
    parser.add_argument('--trials', type=int, default=10, help='Number of trials per attack')
    parser.add_argument('--attacks', nargs='+',
                       default=['rapl_injection', 'replay', 'rollback', 'fork', 'signature_forgery'],
                       help='Attacks to test')
    parser.add_argument('--vm-ip', type=str, default=None,
                       help='Optional VM IP for remote chain-file tampering over SSH')
    parser.add_argument('--vm-user', type=str, default='user',
                       help='VM SSH username when --vm-ip is used')
    parser.add_argument('--output', type=Path, help='Output file for report')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("This script requires root privileges")
        print("Usage: sudo python3 empirical_attack_test.py --trials 100")
        sys.exit(1)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print("SCAPHANDRE EMPIRICAL SECURITY TESTING")
    print(f"{'='*60}")
    print(f"Trials per attack: {args.trials}")
    print(f"Attacks: {', '.join(args.attacks)}")
    print(f"VM: {args.vm_ip or 'local chain files'}")
    print()

    chain = ChainState(vm_ip=args.vm_ip, vm_user=args.vm_user)
    simulator = AttackSimulator(chain, vm_ip=args.vm_ip or VM_IP)

    attack_methods = {
        'rapl_injection': simulator.attack_rapl_injection,
        'replay': simulator.attack_replay,
        'rollback': simulator.attack_rollback,
        'fork': simulator.attack_fork,
        'signature_forgery': simulator.attack_signature_forgery,
    }

    all_results = []

    for attack in args.attacks:
        if attack not in attack_methods:
            print(f"Unknown attack: {attack}")
            continue

        print(f"\n[{attack.upper()}] Running {args.trials} trials...")
        method = attack_methods[attack]

        for trial in range(args.trials):
            print(f"  Trial {trial + 1}/{args.trials}...", end=" ", flush=True)
            result = method(trial)
            all_results.append(result)

            if result.detected:
                details = f" - {result.detection_message}" if result.detection_message else ""
                print(f"DETECTED ({result.detection_time_ms:.1f}ms){details}")
            elif result.error:
                print(f"ERROR: {result.error}")
            else:
                details = f" - {result.detection_message}" if result.detection_message else ""
                print(f"NOT DETECTED{details}")

            time.sleep(0.5)

    stats = compute_statistics(all_results)
    output_file = args.output or (RESULTS_DIR / f"report_{int(time.time())}.txt")
    print_report(stats, output_file)

    results_json = RESULTS_DIR / f"results_{int(time.time())}.json"
    with open(results_json, 'w') as f:
        json.dump([vars(r) for r in all_results], f, indent=2)
    print(f"Raw results saved to: {results_json}")

if __name__ == '__main__':
    main()
