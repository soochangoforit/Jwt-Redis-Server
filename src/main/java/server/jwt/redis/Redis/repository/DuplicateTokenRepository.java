package server.jwt.redis.Redis.repository;

import io.netty.util.internal.ObjectUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import server.jwt.redis.Redis.domain.DuplicateToken;

import java.time.Duration;
import java.util.Objects;

@Component
public class DuplicateTokenRepository  {

    private final RedisTemplate<String,String> duplicateTokenRedisTemplate;

    public DuplicateTokenRepository(@Qualifier("duplicateTokenRedisTemplate") RedisTemplate<String, String> duplicateTokenRedisTemplate) {
        this.duplicateTokenRedisTemplate = duplicateTokenRedisTemplate;
    }


    public ValueOperations<String, String> opsForValue() {
        return duplicateTokenRedisTemplate.opsForValue();
    }

    public void save(String oldToken, String duplicateMessage) {
        opsForValue().set(oldToken, duplicateMessage, Duration.ofMillis(1000 * 60 * 60 * 24 * 1));
    }

    public String findStateByOldToken(String oldRefreshToken) {
        String message = opsForValue().get(oldRefreshToken);

        if(message == null) {
            return null;
        }
        return message;
    }
}
