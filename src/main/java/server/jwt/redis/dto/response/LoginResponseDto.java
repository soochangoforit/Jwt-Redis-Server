package server.jwt.redis.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponseDto {

    private String accessToken;
    // private String refreshToken; refresh token은 cookie로 들어간다.

}
