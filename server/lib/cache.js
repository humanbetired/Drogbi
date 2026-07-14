import Redis from 'ioredis';

const TTL_SECONDS = 6 * 60 * 60; 
let redis = null;
let redisAvailable = false;

export function initCache(redisUrl) {
  try {
    redis = new Redis(redisUrl, {
      retryStrategy: () => null,
      lazyConnect: true,
    });
    redis.on('error', () => {
      redisAvailable = false;
    });
    redis
      .connect()
      .then(() => {
        redisAvailable = true;
      })
      .catch(() => {
        redisAvailable = false;
      });
  } catch {
    redisAvailable = false;
  }
}

function key(iocValue) {
  return `ioc:${iocValue.toLowerCase()}`;
}

export async function getCached(iocValue) {
  if (!redisAvailable || !redis) return null;
  try {
    const raw = await redis.get(key(iocValue));
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export async function setCached(iocValue, data) {
  if (!redisAvailable || !redis) return;
  try {
    await redis.set(key(iocValue), JSON.stringify(data), 'EX', TTL_SECONDS);
  } catch {
    // cache write failures shouldn't break the request
  }
}

export function isCacheAvailable() {
  return redisAvailable;
}