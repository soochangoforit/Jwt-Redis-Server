package server.jwt.redis.Redis.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;

import javax.persistence.Id;
import java.io.Serializable;
import java.util.Set;

@Getter
@NoArgsConstructor
public class DuplicateToken implements Serializable {

    private String state;

    @Builder
    public DuplicateToken(String state) {
        this.state = state;
    }
}
