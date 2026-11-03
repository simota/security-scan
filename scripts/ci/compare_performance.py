#!/usr/bin/env python3
"""Pair two isolated revisions without overlapping their timed operations.

Both workers use this checkout's benchmark fixtures and measurement code. Each
revision imports its own scripts in a separate interpreter. The parent alternates
which revision runs first; fixture preparation, IPC and hashing are not timed.
Arguments after -- are passed unchanged to the selected benchmark suite.
"""
import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
import math
import os
from pathlib import Path
import random
import selectors
import statistics
import subprocess
import sys
import time

import benchmark_performance


def summary(wall, cpu, digest):
    ordered = sorted(wall)
    return {"samples_seconds": wall, "cpu_samples_seconds": cpu,
            "mean_seconds": statistics.mean(wall), "median_seconds": statistics.median(wall),
            "p95_seconds": ordered[math.ceil(len(wall) * .95) - 1],
            "p99_seconds": ordered[math.ceil(len(wall) * .99) - 1],
            "median_cpu_seconds": statistics.median(cpu),
            "operations_per_second": 1 / statistics.mean(wall), "output_sha256": digest}


def worker(args, forwarded):
    if args.suite == "pipeline":
        import benchmark_pipeline as suite
    else:
        suite = benchmark_performance
    protocol = sys.stdout
    index = 0

    def emit(value):
        print(json.dumps(value), file=protocol, flush=True)

    original_measure = benchmark_performance.measure

    def controlled_measure(prepare, operation, repeats, memory=False, metrics=False):
        nonlocal index
        wall, cpu, expected, peaks, rss = [], [], None, None, None

        def once():
            nonlocal expected
            payload = prepare()
            start_cpu, start_wall = time.process_time(), time.perf_counter()
            result = operation(payload)
            elapsed_wall = time.perf_counter() - start_wall
            elapsed_cpu = time.process_time() - start_cpu
            encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8")
            digest = hashlib.sha256(encoded).hexdigest()
            if expected is not None and digest != expected:
                raise RuntimeError("workload output changed between samples")
            expected = digest
            return elapsed_wall, elapsed_cpu

        for _ in range(3):
            once()
        emit({"event": "ready", "index": index, "output_sha256": expected})
        while True:
            command = sys.stdin.readline().strip()
            if command == "sample":
                elapsed_wall, elapsed_cpu = once()
                wall.append(elapsed_wall)
                cpu.append(elapsed_cpu)
                emit({"event": "sample", "wall_seconds": elapsed_wall,
                      "cpu_seconds": elapsed_cpu, "output_sha256": expected})
            elif command == "rss":
                rss = benchmark_performance.process_peak_rss()
                emit({"event": "rss", "bytes": rss})
            elif command == "memory":
                traced = original_measure(prepare, operation, 1, memory=True, metrics=True)
                if traced["output_sha256"] != expected:
                    raise RuntimeError("traced workload output changed")
                peaks = traced["traced_peak_bytes"]
                emit({"event": "memory", "traced_peak_bytes": peaks})
            elif command == "finish":
                if len(wall) != args.samples:
                    raise RuntimeError("unexpected sample count")
                measured = summary(wall, cpu, expected)
                measured["worker_peak_rss_bytes_so_far"] = rss
                if peaks is not None:
                    measured["traced_peak_bytes"] = peaks
                index += 1
                return measured
            else:
                raise RuntimeError("unknown benchmark command or closed input")

    suite.measure = controlled_measure
    captured = io.StringIO()
    with redirect_stdout(captured):
        result = suite.main(forwarded + ["--scripts-dir", str(args.scripts_dir), "--repeats", str(args.samples)])
    if result:
        raise RuntimeError("benchmark suite failed")
    data = json.loads(captured.getvalue())
    data["rss_includes_tracemalloc"] = args.memory
    emit({"event": "complete", "result": data})


def receive(process, timeout):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise RuntimeError("benchmark worker exceeded the response timeout")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("benchmark worker exited: " + process.stderr.read()[-8000:])
    return json.loads(line)


def send(process, command):
    process.stdin.write(command + "\n")
    process.stdin.flush()


def ratio_interval(before, after):
    """Percentile bootstrap for the paired mean ratio; no significance gate."""
    generator = random.Random(20261104)
    ratios = []
    for _ in range(3000):
        indexes = [generator.randrange(len(before)) for _ in before]
        ratios.append(sum(after[i] for i in indexes) / sum(before[i] for i in indexes))
    ratios.sort()
    return [ratios[74], ratios[2924]]


def compare(args, forwarded):
    processes = {}
    try:
        for label, directory in (("before", args.before), ("after", args.after)):
            command = [sys.executable, str(Path(__file__).resolve()), "--worker", "--suite", args.suite,
                       "--scripts-dir", str(directory.resolve()), "--samples", str(args.samples)]
            if args.cpu is not None:
                command += ["--cpu", str(args.cpu)]
            if args.memory:
                command.append("--memory")
            command += ["--"] + forwarded
            processes[label] = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE, text=True, bufsize=1)
        state = {name: receive(process, args.timeout) for name, process in processes.items()}
        while state["before"]["event"] == "ready":
            if state["after"]["event"] != "ready" or state["before"]["index"] != state["after"]["index"]:
                raise RuntimeError("revision workload sequences differ")
            if state["before"]["output_sha256"] != state["after"]["output_sha256"]:
                raise RuntimeError("revision outputs differ before timing")
            for repetition in range(args.samples):
                order = ("before", "after") if repetition % 2 == 0 else ("after", "before")
                for name in order:
                    send(processes[name], "sample")
                    sample = receive(processes[name], args.timeout)
                    if sample["event"] != "sample" or sample["output_sha256"] != state[name]["output_sha256"]:
                        raise RuntimeError("revision output changed while timing")
            for process in processes.values():
                send(process, "rss")
                if receive(process, args.timeout)["event"] != "rss":
                    raise RuntimeError("missing RSS measurement")
                if args.memory:
                    send(process, "memory")
                    if receive(process, args.timeout)["event"] != "memory":
                        raise RuntimeError("missing allocation measurement")
            print("Completed paired workload %d" % (state["before"]["index"] + 1), file=sys.stderr, flush=True)
            for process in processes.values():
                send(process, "finish")
            state = {name: receive(process, args.timeout) for name, process in processes.items()}
        if any(value["event"] != "complete" for value in state.values()):
            raise RuntimeError("revision workload counts differ")
        for process in processes.values():
            if process.wait(timeout=5) != 0:
                raise RuntimeError("benchmark worker failed after producing its result")
        results = {name: value["result"] for name, value in state.items()}
        comparisons = {}
        for name, before in results["before"]["workloads"].items():
            after = results["after"]["workloads"][name]
            if before["output_sha256"] != after["output_sha256"]:
                raise RuntimeError("revision output hashes differ")
            comparisons[name] = {
                "median_change_percent": 100 * (after["median_seconds"] / before["median_seconds"] - 1),
                "mean_ratio_ci95": ratio_interval(before["samples_seconds"], after["samples_seconds"]),
                "cpu_mean_ratio_ci95": ratio_interval(before["cpu_samples_seconds"], after["cpu_samples_seconds"]),
                "output_identical": True,
            }
        return {"suite": args.suite, "samples_per_revision": args.samples,
                "warmups": 3, "cpu_affinity": args.cpu, "hash_seed": os.environ.get("PYTHONHASHSEED"),
                "measurement": "isolated workers, alternating paired operations; setup/copies/IPC/hashes excluded",
                "rss_scope": "whole worker lifetime; earlier workloads and any earlier tracing are included",
                "comparisons": comparisons, **results}
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--suite", choices=("existing", "pipeline"), default="pipeline")
    parser.add_argument("--samples", type=benchmark_performance.positive_int, default=21)
    parser.add_argument("--memory", action="store_true")
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--timeout", type=benchmark_performance.positive_int, default=120)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--scripts-dir", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("benchmark_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    forwarded = args.benchmark_args[1:] if args.benchmark_args[:1] == ["--"] else args.benchmark_args
    reserved = ("--scripts-dir", "--repeats", "--memory")
    for argument in forwarded:
        option = argument.split("=", 1)[0]
        if option.startswith("--") and any(name.startswith(option) for name in reserved):
            parser.error("comparison owns --scripts-dir, --repeats and --memory; use --before/--after, --samples and --memory before --")
    if args.cpu is not None:
        if not hasattr(os, "sched_setaffinity") or args.cpu < 0:
            parser.error("--cpu requires a supported nonnegative CPU affinity")
        os.sched_setaffinity(0, {args.cpu})
    if args.worker:
        if args.scripts_dir is None:
            parser.error("worker requires --scripts-dir")
        worker(args, forwarded)
    else:
        if args.before is None or args.after is None:
            parser.error("--before and --after script directories are required")
        print(json.dumps(compare(args, forwarded), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
