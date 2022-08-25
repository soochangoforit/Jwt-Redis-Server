package server.jwt.redis.Redis.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;

import javax.persistence.Id;
import java.io.Serializable;

@Getter
@NoArgsConstructor
public class IdToToken implements Serializable {

    //value
    private String refreshToken;

    @Builder
    public IdToToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
