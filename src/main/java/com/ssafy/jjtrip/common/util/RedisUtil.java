package com.ssafy.jjtrip.common.util;

import java.time.Duration;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RedisUtil {

    private final StringRedisTemplate stringRedisTemplate;

    public void set(String key, String value, long expireTimeMs) {
        stringRedisTemplate.opsForValue().set(key, value, Duration.ofMillis(expireTimeMs));
    }

    public String get(String key) {
        return stringRedisTemplate.opsForValue().get(key);
    }

    public void delete(String key) {
        stringRedisTemplate.delete(key);
    }

    public boolean hasKey(String key) {
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(key));
    }

    public void zadd(String key, String value, double score) {
        stringRedisTemplate.opsForZSet().add(key, value, score);
    }

    public Set<String> zrevrange(String key, long start, long end) {
        return stringRedisTemplate.opsForZSet().reverseRange(key, start, end);
    }

    public Set<ZSetOperations.TypedTuple<String>> zrevrangeByScoreWithScores(
            String key, double min, double max, long offset, long count
    ) {
        return stringRedisTemplate.opsForZSet().reverseRangeByScoreWithScores(key, min, max, offset, count);
    }
}
