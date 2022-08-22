package server.jwt.redis.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class SignUpRequestDto {

    private String username;
    private String password;
    private String email;
    private String nickname;

}
