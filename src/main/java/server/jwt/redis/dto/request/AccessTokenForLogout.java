package server.jwt.redis.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class AccessTokenForLogout {
    private String accessToken;
}
