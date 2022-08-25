package server.jwt.redis.Redis.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;
import server.jwt.redis.Redis.domain.LogoutToken;

import java.time.Duration;

@Component
public class LogoutTokenRepository {

    private final RedisTemplate<String, Object> logoutTokenRedisTemplate;

    public LogoutTokenRepository(@Qualifier("logoutTokenRedisTemplate") RedisTemplate<String, Object> logoutTokenRedisTemplate) {
        this.logoutTokenRedisTemplate = logoutTokenRedisTemplate;
    }

    public ValueOperations<String, Object> opsForValue() {
        return logoutTokenRedisTemplate.opsForValue();
    }

    public void save(String accessToken, String logout, Duration ofMillis) {
        LogoutToken.builder()
                .state(logout)
                .build();

        opsForValue().set(accessToken, logout, ofMillis);
    }

    public LogoutToken findLogoutToken(String logoutToken) {

        return (LogoutToken) opsForValue().get(logoutToken);
    }
}
