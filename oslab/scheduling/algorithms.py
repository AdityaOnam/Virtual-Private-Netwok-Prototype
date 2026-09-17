"""
oslab.scheduling.algorithms — CPU scheduling, run over real work.

Four classic algorithms, scheduling actual probe jobs rather than a simulation.
The same job set goes through each, so the comparison is like for like.

    FCFS      First Come First Served. Run to completion in arrival order.
              Simple and fair in intent, terrible in effect: one long job at
              the front delays everything behind it. This is the convoy effect.

    SJF       Shortest Job First. Provably optimal for average waiting time —
              and unimplementable in general, because it needs to know how long
              each job will take before running it. Real schedulers estimate
              from history. Long jobs can starve.

    RR        Round Robin. Each job gets a quantum, then goes to the back of
              the queue. Fair and responsive; the quantum is the whole design.
              Too large and it degenerates to FCFS; too small and context
              switches dominate.

    Priority  Highest priority first. Starves low-priority jobs unless aging
              raises their priority the longer they wait — which is what the
              `aging` parameter below does.

Metrics
───────
    waiting time     = turnaround - service   (time spent not running)
    turnaround time  = completion - arrival   (total time in the system)
    response time    = first run - arrival    (time until anything happens)

Response time is the one interactive users feel. Round Robin wins on it and
loses on turnaround, which is exactly the trade an interactive scheduler makes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Job:
    """A unit of work with a known duration (measured, or estimated)."""

    job_id: int
    name: str
    duration: float
    arrival: float = 0.0
    priority: int = 5          # lower number = higher priority

    # Filled in by the scheduler
    started: float | None = None
    completed: float | None = None
    remaining: float = field(init=False)
    first_run: float | None = None

    def __post_init__(self) -> None:
        self.remaining = self.duration

    @property
    def waiting_time(self) -> float:
        if self.completed is None:
            return 0.0
        return (self.completed - self.arrival) - self.duration

    @property
    def turnaround_time(self) -> float:
        if self.completed is None:
            return 0.0
        return self.completed - self.arrival

    @property
    def response_time(self) -> float:
        if self.first_run is None:
            return 0.0
        return self.first_run - self.arrival


@dataclass
class Slice:
    """One contiguous period a job held the CPU — a bar in the Gantt chart."""

    job_id: int
    name: str
    start: float
    end: float

    @property
    def duration(self) -> float:
        return self.end - self.start


@dataclass
class ScheduleResult:
    algorithm: str
    jobs: list[Job]
    timeline: list[Slice]
    context_switches: int = 0
    quantum: float | None = None

    @property
    def makespan(self) -> float:
        return max((j.completed or 0.0) for j in self.jobs) if self.jobs else 0.0

    def metrics(self) -> dict:
        if not self.jobs:
            return {"algorithm": self.algorithm, "jobs": 0}
        count = len(self.jobs)
        return {
            "algorithm": self.algorithm,
            "jobs": count,
            "quantum": self.quantum,
            "avg_waiting": round(sum(j.waiting_time for j in self.jobs) / count, 3),
            "avg_turnaround": round(
                sum(j.turnaround_time for j in self.jobs) / count, 3),
            "avg_response": round(
                sum(j.response_time for j in self.jobs) / count, 3),
            "makespan": round(self.makespan, 3),
            "context_switches": self.context_switches,
        }

    def gantt(self, width: int = 60) -> str:
        """Render the timeline as text — the classic teaching diagram."""
        if not self.timeline:
            return "(no jobs)"
        span = self.makespan or 1.0
        lines = [f"{self.algorithm}  (makespan {span:.3f}s, "
                 f"{self.context_switches} switches)"]
        by_job: dict[int, list[Slice]] = {}
        for item in self.timeline:
            by_job.setdefault(item.job_id, []).append(item)

        for job in self.jobs:
            row = [" "] * width
            for item in by_job.get(job.job_id, []):
                start = int(item.start / span * width)
                end = max(start + 1, int(item.end / span * width))
                for column in range(start, min(end, width)):
                    row[column] = "█"
            lines.append(f"  {job.name:12} |{''.join(row)}|")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Algorithms
# ─────────────────────────────────────────────────────────────────────────────

def schedule_fcfs(jobs: list[Job]) -> ScheduleResult:
    """Run each job to completion in arrival order."""
    ordered = sorted(jobs, key=lambda j: (j.arrival, j.job_id))
    now = 0.0
    timeline: list[Slice] = []

    for job in ordered:
        now = max(now, job.arrival)
        job.started = job.first_run = now
        now += job.duration
        job.completed = now
        job.remaining = 0.0
        timeline.append(Slice(job.job_id, job.name, job.started, now))

    return ScheduleResult("FCFS", ordered, timeline,
                          context_switches=max(0, len(ordered) - 1))


def schedule_sjf(jobs: list[Job]) -> ScheduleResult:
    """
    Shortest Job First, non-preemptive.

    Optimal for average waiting time, and impossible to implement honestly:
    it requires knowing each job's duration in advance. Here the durations are
    measured beforehand, which is the cheat that makes the comparison possible.
    """
    pending = sorted(jobs, key=lambda j: (j.arrival, j.job_id))
    now = 0.0
    order: list[Job] = []
    timeline: list[Slice] = []
    remaining = list(pending)

    while remaining:
        ready = [j for j in remaining if j.arrival <= now] or [remaining[0]]
        job = min(ready, key=lambda j: (j.duration, j.arrival, j.job_id))
        remaining.remove(job)

        now = max(now, job.arrival)
        job.started = job.first_run = now
        now += job.duration
        job.completed = now
        job.remaining = 0.0
        order.append(job)
        timeline.append(Slice(job.job_id, job.name, job.started, now))

    return ScheduleResult("SJF", order, timeline,
                          context_switches=max(0, len(order) - 1))


def schedule_round_robin(jobs: list[Job], quantum: float = 0.05,
                         switch_cost: float = 0.0) -> ScheduleResult:
    """
    Round Robin with a fixed quantum.

    `switch_cost` charges each context switch, which is what makes a tiny
    quantum bad: halve the quantum and you double the switches, and at some
    point the scheduler spends more time switching than working.
    """
    if quantum <= 0:
        raise ValueError(f"quantum must be positive, got {quantum}")

    ordered = sorted(jobs, key=lambda j: (j.arrival, j.job_id))
    now = 0.0
    queue: list[Job] = []
    pending = list(ordered)
    timeline: list[Slice] = []
    switches = 0

    while pending or queue:
        while pending and pending[0].arrival <= now:
            queue.append(pending.pop(0))
        if not queue:
            now = pending[0].arrival
            continue

        job = queue.pop(0)
        if job.first_run is None:
            job.first_run = now
        if job.started is None:
            job.started = now

        run_for = min(quantum, job.remaining)
        timeline.append(Slice(job.job_id, job.name, now, now + run_for))
        now += run_for
        job.remaining -= run_for

        while pending and pending[0].arrival <= now:
            queue.append(pending.pop(0))

        if job.remaining > 1e-9:
            queue.append(job)          # back of the queue
            switches += 1
            now += switch_cost
        else:
            job.completed = now
            if queue or pending:
                switches += 1
                now += switch_cost

    return ScheduleResult("Round Robin", ordered, timeline,
                          context_switches=switches, quantum=quantum)


def schedule_priority(jobs: list[Job], aging: float = 0.0) -> ScheduleResult:
    """
    Non-preemptive priority scheduling, with optional aging.

    Without aging, a stream of high-priority jobs starves the low-priority
    ones indefinitely. `aging` raises a waiting job's effective priority by
    that much per second, which guarantees it eventually runs — the standard
    fix, and the reason aging exists at all.
    """
    pending = sorted(jobs, key=lambda j: (j.arrival, j.job_id))
    now = 0.0
    order: list[Job] = []
    timeline: list[Slice] = []
    remaining = list(pending)

    while remaining:
        ready = [j for j in remaining if j.arrival <= now] or [remaining[0]]

        def effective(job: Job) -> float:
            waited = max(0.0, now - job.arrival)
            return job.priority - aging * waited

        job = min(ready, key=lambda j: (effective(j), j.arrival, j.job_id))
        remaining.remove(job)

        now = max(now, job.arrival)
        job.started = job.first_run = now
        now += job.duration
        job.completed = now
        job.remaining = 0.0
        order.append(job)
        timeline.append(Slice(job.job_id, job.name, job.started, now))

    return ScheduleResult("Priority", order, timeline,
                          context_switches=max(0, len(order) - 1))


ALGORITHMS: dict[str, Callable] = {
    "fcfs": schedule_fcfs,
    "sjf": schedule_sjf,
    "rr": schedule_round_robin,
    "priority": schedule_priority,
}


def compare_algorithms(jobs: list[Job], quantum: float = 0.05) -> dict:
    """
    Run every algorithm over the same job set.

    Each algorithm gets its own copies, because scheduling mutates the jobs.
    """
    import copy

    results = {
        "fcfs": schedule_fcfs(copy.deepcopy(jobs)),
        "sjf": schedule_sjf(copy.deepcopy(jobs)),
        "rr": schedule_round_robin(copy.deepcopy(jobs), quantum=quantum),
        "priority": schedule_priority(copy.deepcopy(jobs)),
    }
    return {
        "results": results,
        "metrics": {name: result.metrics() for name, result in results.items()},
        "best_avg_waiting": min(
            results, key=lambda n: results[n].metrics()["avg_waiting"]
        ),
        "best_avg_response": min(
            results, key=lambda n: results[n].metrics()["avg_response"]
        ),
    }


def jobs_from_measurements(measurements: list[tuple[str, float]],
                           priorities: list[int] | None = None) -> list[Job]:
    """
    Build a job set from real measured durations.

    The scheduler panel measures how long each server probe actually took, then
    schedules those durations — so the Gantt chart describes work that really
    happened rather than invented numbers.
    """
    return [
        Job(
            job_id=index,
            name=name,
            duration=duration,
            arrival=0.0,
            priority=(priorities[index] if priorities and index < len(priorities)
                      else 5),
        )
        for index, (name, duration) in enumerate(measurements)
    ]
