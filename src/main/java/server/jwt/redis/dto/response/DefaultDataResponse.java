package server.jwt.redis.dto.response;

import lombok.*;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Setter
@Builder
public class DefaultDataResponse<T> {

    private int status;
    private String message;
    private T data;

    public static<T> DefaultDataResponse<T> of(int status, String message, T data) {
        return DefaultDataResponse.<T>builder()
                .status(status)
                .message(message)
                .data(data)
                .build();
    }

}
