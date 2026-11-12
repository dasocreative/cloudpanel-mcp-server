import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Mutex, Semaphore } from "../src/mutex.ts";

const tick = (ms = 5): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe("Mutex", () => {
  it("runs jobs one at a time, in order, and survives a failing job", async () => {
    const mutex = new Mutex();
    const log: string[] = [];
    const job = (name: string, fail = false) => async () => {
      log.push(`start ${name}`);
      await tick();
      log.push(`end ${name}`);
      if (fail) throw new Error(name);
      return name;
    };
    const results = await Promise.allSettled([mutex.run(job("a")), mutex.run(job("b", true)), mutex.run(job("c"))]);
    assert.deepEqual(log, ["start a", "end a", "start b", "end b", "start c", "end c"]);
    assert.deepEqual(results.map((r) => r.status), ["fulfilled", "rejected", "fulfilled"]);
  });
});

describe("Semaphore", () => {
  it("never runs more than `max` jobs at once, and starts the waiting ones in order", async () => {
    const gate = new Semaphore(3);
    let active = 0;
    let most = 0;
    const started: number[] = [];
    const jobs = Array.from({ length: 12 }, (_, i) => gate.run(async () => {
      started.push(i);
      active += 1;
      most = Math.max(most, active);
      await tick(10);
      active -= 1;
      return i;
    }));
    assert.deepEqual(await Promise.all(jobs), Array.from({ length: 12 }, (_, i) => i));
    assert.equal(most, 3);
    assert.deepEqual(started, Array.from({ length: 12 }, (_, i) => i));
  });
  it("hands a finished job's place to the next waiter: a caller that arrives at that moment cannot slip in", async () => {
    const gate = new Semaphore(2);
    let active = 0;
    let most = 0;
    const job = (ms: number, then?: () => void) => async (): Promise<void> => {
      active += 1;
      most = Math.max(most, active);
      await tick(ms);
      then?.();
      active -= 1;
    };
    const barging: Promise<void>[] = [];
    // when the first job ends, new callers arrive in the same tick, while three others are already waiting
    const first = gate.run(job(5, () => { for (let i = 0; i < 4; i += 1) barging.push(gate.run(job(5))); }));
    const second = gate.run(job(30));
    const waiting = [1, 2, 3].map(() => gate.run(job(10)));
    await Promise.all([first, second, ...waiting]);
    await Promise.all(barging);
    assert.equal(most, 2);
  });
  it("a caller that arrives right after a job finished waits behind the waiter that got its place", async () => {
    const gate = new Semaphore(1);
    let active = 0;
    let most = 0;
    const job = (ms: number) => async (): Promise<void> => {
      active += 1;
      most = Math.max(most, active);
      await tick(ms);
      active -= 1;
    };
    const a = gate.run(job(2));
    const b = gate.run(job(30));
    await a;
    const c = gate.run(job(2)); // B holds the place now; C must not run beside it
    await Promise.all([b, c]);
    assert.equal(most, 1);
  });
  it("frees the place of a job that throws", async () => {
    const gate = new Semaphore(1);
    await assert.rejects(gate.run(async () => { throw new Error("boom"); }), /boom/);
    assert.equal(await gate.run(async () => "next"), "next");
  });
  it("with one place it is a queue", async () => {
    const gate = new Semaphore(1);
    const order: string[] = [];
    await Promise.all(["a", "b", "c"].map((n) => gate.run(async () => { order.push(`${n}1`); await tick(); order.push(`${n}2`); })));
    assert.deepEqual(order, ["a1", "a2", "b1", "b2", "c1", "c2"]);
  });
});
