const buckets = new Map<string, { count: number; resetAt: number }>();

type RateLimitOptions = {
  windowMs: number;
  max: number;
};

export function rateLimit(key: string, options: RateLimitOptions) {
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || bucket.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + options.windowMs });
    return { allowed: true, remaining: options.max - 1 };
  }

  if (bucket.count >= options.max) {
    return { allowed: false, remaining: 0 };
  }

  bucket.count += 1;
  buckets.set(key, bucket);
  return { allowed: true, remaining: options.max - bucket.count };
}
