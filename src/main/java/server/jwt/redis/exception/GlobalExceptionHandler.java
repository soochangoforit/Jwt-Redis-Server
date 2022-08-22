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

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<BasicResponse> handle(BadRequestException e) {
        BasicResponse exceptionDto = new BasicResponse(e.getMessage(), HttpStatus.BAD_REQUEST);
        return new ResponseEntity<>(exceptionDto, HttpStatus.BAD_REQUEST);
    }

    /**
     * 토큰의 형식이 맞지 않는 경우
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<BasicResponse> handle(BadCredentialsException e) {
        BasicResponse exceptionDto = new BasicResponse(e.getMessage(), HttpStatus.UNAUTHORIZED);
        return new ResponseEntity<>(exceptionDto, HttpStatus.UNAUTHORIZED);
    }

}