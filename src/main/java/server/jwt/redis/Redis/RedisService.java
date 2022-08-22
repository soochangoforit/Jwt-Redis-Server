package server.jwt.redis.Redis;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import server.jwt.redis.exception.BadRequestException;

import java.time.Duration;
import java.util.Objects;

/**
 * 이제 아래의 메서드를 통해 redis 저장소에 Key-Value 쌍으로 데이터를 넣고 가져오며 삭제 가능하다.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RedisService {
    private final RedisTemplate<String, Object> redisTemplate;

    @Transactional
    public void setRefreshValues(String key_refresh_token, String clientIp, Long userId, Duration duration) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();

        RedisValue redisValue = new RedisValue(clientIp, userId.toString());

        values.set(key_refresh_token, redisValue, duration);
    }

    @Transactional
    public void setLogoutAccessValues(String logout_access_token, String message, Duration duration) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();

        RedisValue redisValue = new RedisValue(message,message);

        values.set(logout_access_token, redisValue, duration);
    }


    public String getValuesForClientIp(String key_refresh_token) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();
        RedisValue redisValue = (RedisValue) values.get(key_refresh_token);

        // refresh token이 유효기간이 지나서 redis에서 삭제되었을때
        // 혹은 로그아웃 되어서 토큰이 사라진 경우
        if (Objects.isNull(redisValue)) {
            throw new BadRequestException("존재하지 않는 Refresh Token입니다.");
        }


        String clientIp = redisValue.getClientIp();

        return clientIp;
    }

    public void deleteValues(String key) {
        redisTemplate.delete(key);
    }


    @Transactional
    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(refreshToken);
    }
}
