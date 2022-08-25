package server.jwt.redis.Redis.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import server.jwt.redis.Redis.domain.TokenToIpWithId;
import server.jwt.redis.exception.BadRequestException;

import java.time.Duration;

@Component
public class TokenToIpWithIdRepository {

    private final RedisTemplate<String, Object> tokenToIpWithIdRedisTemplate;

    public TokenToIpWithIdRepository(@Qualifier("tokenToIpWithIdRedisTemplate") RedisTemplate<String, Object> tokenToIpWithIdRedisTemplate) {
        this.tokenToIpWithIdRedisTemplate = tokenToIpWithIdRedisTemplate;
    }

    public ValueOperations<String, Object> opsForValue() {
        return tokenToIpWithIdRedisTemplate.opsForValue();
    }

    public void save(String refreshToken, TokenToIpWithId tokenToIpWithId) {
        // 1 day expire
        opsForValue().set(refreshToken, tokenToIpWithId, Duration.ofMillis(1000 * 60 * 60 * 24 * 1));
    }

    public void delete(String oldToken) {
        tokenToIpWithIdRedisTemplate.delete(oldToken);
    }

    public TokenToIpWithId findValueByToken(String oldRefreshToken) {
        TokenToIpWithId tokenToIpWithId = (TokenToIpWithId) opsForValue().get(oldRefreshToken);

        if(tokenToIpWithId == null) {
            throw new BadRequestException("존재하지 않는 Refresh Token입니다.");
        }

        return tokenToIpWithId;
    }
}
