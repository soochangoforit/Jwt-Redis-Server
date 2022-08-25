package server.jwt.redis.Redis.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Getter
@NoArgsConstructor
public class LogoutToken implements Serializable {

    private String state; // logout message

    @Builder
    public LogoutToken(String state) {
        this.state = state;
    }

}
