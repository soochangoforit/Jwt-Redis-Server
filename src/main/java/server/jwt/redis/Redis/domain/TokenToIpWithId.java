package server.jwt.redis.Redis.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;

import javax.persistence.Id;
import java.io.Serializable;

@Getter
@NoArgsConstructor
public class TokenToIpWithId implements Serializable {

    // value
    private String clientIp;
    private String userId;

    @Builder
    public TokenToIpWithId(String clientIp, String userId) {
        this.clientIp = clientIp;
        this.userId = userId;
    }


}
