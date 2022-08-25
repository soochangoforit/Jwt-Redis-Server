package server.jwt.redis.Redis.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;
import server.jwt.redis.Redis.domain.IdToToken;

import java.time.Duration;

@Component

public class IdToTokenRepository  {

    private final RedisTemplate<String, Object> idToTokenRedisTemplate;

    public IdToTokenRepository(@Qualifier("idToTokenRedisTemplate") RedisTemplate<String, Object> idToTokenRedisTemplate) {
        this.idToTokenRedisTemplate = idToTokenRedisTemplate;
    }

    public ValueOperations<String, Object> opsForValue() {
        return idToTokenRedisTemplate.opsForValue();
    }

    public String findTokenById(String id) {
        IdToToken idToToken = (IdToToken) opsForValue().get(id);

        if(idToToken == null) {
            return null;
        }
        return idToToken.getRefreshToken();
    }


    public void save(Long userId, IdToToken idToToken) {
        // 1 day expire
        opsForValue().set(userId.toString(), idToToken, Duration.ofMillis(1000 * 60 * 60 * 24 * 1));
    }

    public void delete(String userId) {
        idToTokenRedisTemplate.delete(userId);
    }
}
