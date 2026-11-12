/** Runs one async job at a time, in order. */
export class Mutex {
  private tail: Promise<unknown> = Promise.resolve();

  run<T>(job: () => Promise<T>): Promise<T> {
    const result = this.tail.then(job, job);
    this.tail = result.catch(() => undefined);
    return result;
  }
}

/** Runs at most `max` async jobs at a time; the rest wait their turn, in order. */
export class Semaphore {
  private active = 0;
  private readonly waiting: (() => void)[] = [];
  private readonly max: number;

  constructor(max: number) {
    this.max = max;
  }

  async run<T>(job: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) {
      // the slot is handed over by the job that finishes: `active` stays as it is, so nobody can slip in between
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    } else {
      this.active += 1;
    }
    try {
      return await job();
    } finally {
      const next = this.waiting.shift();
      if (next !== undefined) next();
      else this.active -= 1;
    }
  }
}
