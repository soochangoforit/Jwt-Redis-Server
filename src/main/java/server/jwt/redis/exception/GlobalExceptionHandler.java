package server.jwt.redis.exception;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import server.jwt.redis.dto.response.BasicResponse;

@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    /**
     * 400 Bad Request
     * 클라이언트가 잘못된 요청을 해서 서버가 요청을 처리할 수 없음
     */
    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<BasicResponse> handle(BadRequestException e) {
        BasicResponse exceptionDto = new BasicResponse(HttpStatus.BAD_REQUEST.value(), e.getMessage());
        return new ResponseEntity<>(exceptionDto, HttpStatus.BAD_REQUEST);
    }

    /**
     * 토큰의 형식이 맞지 않는 경우 혹은 해킹이 의심되거나 IP주소가 달라진경우
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<BasicResponse> handle(BadCredentialsException e) {
        BasicResponse exceptionDto = new BasicResponse(HttpStatus.UNAUTHORIZED.value(),e.getMessage());
        return new ResponseEntity<>(exceptionDto, HttpStatus.UNAUTHORIZED);
    }

}