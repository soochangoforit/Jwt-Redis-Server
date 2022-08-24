package server.jwt.redis.Redis;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import server.jwt.redis.exception.BadRequestException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 이제 아래의 메서드를 통해 redis 저장소에 Key-Value 쌍으로 데이터를 넣고 가져오며 삭제 가능하다.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RedisService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisTemplate<String, String> redisTemplateForUserId;

    private final RedisTemplate<String, String> redisTemplateForDuplicateLogin;

    /**
     * key : refresh token
     * value : client ip, userId
     */
    @Transactional
    public void setRefreshValues(String key_refresh_token, String clientIp, Long userId, Duration duration) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();

        RedisValue redisValue = new RedisValue(clientIp, userId.toString());

        values.set(key_refresh_token, redisValue, duration);
    }

    /**
     * key : BLACK_LIST_ACCESS_TOKEN
     * value : "logout" , "logout"
     */
    @Transactional
    public void setLogoutAccessValues(String logout_access_token, String message, Duration duration) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();

        RedisValue redisValue = new RedisValue(message,message);

        values.set(logout_access_token, redisValue, duration);
    }


    /**
     * looking for client ip
     * key : refresh token
     * value : client ip, userId
     */
    public Map<String,String> getValuesForClientIp(String old_key_refresh_token) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();
        RedisValue redisValue = (RedisValue) values.get(old_key_refresh_token);

        // refresh token이 유효기간이 지나서 redis에서 삭제되었을때
        // 혹은 로그아웃 되어서 토큰이 사라진 경우
        // todo : 무결성 때문에 없어진건지 확인, 중복 로그인에 의해서는 따로 처리 완료
        if (Objects.isNull(redisValue)) {
            throw new BadRequestException("존재하지 않는 Refresh Token입니다.");
        }


        String clientIp = redisValue.getClientIp();
        String userId = redisValue.getUserId();

        Map<String,String> map = new HashMap<>();
        map.put("realClientIp",clientIp);
        map.put("userId",userId);

        return map;
    }



    /**
     * delete key : refresh token
     */
    @Transactional
    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(refreshToken);
    }


    /**
     * 로그인 시도시, userId에 대해서 발급 받은 refresh token 저장
     * key : userId
     * value : refresh token
     */
    public void setUserIdWithRefreshToken(Long userId, String refreshToken, Duration duration) {
        ValueOperations<String, String> values = redisTemplateForUserId.opsForValue();
        values.set(userId.toString(), refreshToken, duration);
    }

    public String findTokenByUserId(Long userId) {
        String oldToken = redisTemplateForUserId.opsForValue().get(userId.toString());

        // todo : old token이 없는 경우, 최초 로그인을 진행하겠다는 의미이다.
        if (Objects.isNull(oldToken)) {
            return null;
        }

        return oldToken;
    }

    /**
     * 중복 로그인된 old Refresh Token에 대해서는 Message Queue에다가 "duplicate" 메시지를 남겨준다.
     * key : old refresh token
     * value : "duplicate"
     */
    public void setOldTokenToMessageQueue(String oldToken, String duplicate, Duration duration) {
        ValueOperations<String, String> values = redisTemplateForDuplicateLogin.opsForValue();
        values.set(oldToken, duplicate, duration);
    }


    /**
     * old refresh token으로 duplicate가 있는지 확인한다.
     */
    public String findOldTokenFromDuplicate(String oldRefreshToken) {

        String duplicate = redisTemplateForDuplicateLogin.opsForValue().get(oldRefreshToken);
        if (Objects.isNull(duplicate)) {
            return null;
        }
        return duplicate;
    }

    /**
     * 로그 아웃시, userId에 해당 하는 key 값 삭제
     */
    public void deleteByUserId(String userId) {
        redisTemplateForUserId.delete(userId);
    }
}
