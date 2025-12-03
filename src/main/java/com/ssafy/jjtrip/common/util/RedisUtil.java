package com.ssafy.jjtrip.common.util;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
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

    public void setBlackList(String key, String value, long expireTimeMs) {
        stringRedisTemplate.opsForValue().set(key, value, Duration.ofMillis(expireTimeMs));
    }

    public boolean hasKeyBlackList(String key) {
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(key));
    }
}