package server.jwt.redis.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public class BasicResponse {

    private int status;
    private String message;

    public static BasicResponse of(int status, String message) {
        return new BasicResponse(status, message);
    }

}
