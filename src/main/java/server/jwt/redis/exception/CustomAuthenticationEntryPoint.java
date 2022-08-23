package server.jwt.redis.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import server.jwt.redis.dto.response.BasicResponse;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 이제 마지막으로 토큰 인증에 대한 예외를 처리하는 EntryPoint를 작성한다.
 * jwtProvider에서 토근 검증에 실패하면 발생하는 예외를 catch하여 request의 attribute에 exception을 추가했다.
 *
 * 이제 추가했던 exception을 꺼내어 이에 대한 처리를 진행한다.
 *
 * 에러 메시지와 HttpsStatus.FORBIDDEN을 통해 이전에 작성했던 BasicResponse 만든 뒤, 이를 JSON으로 변환하여 response에 넣어 응답한다
 */
@Getter
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String exception = (String) request.getAttribute("exception");
        setResponse(response);
        BasicResponse exceptionDto = new BasicResponse(HttpStatus.FORBIDDEN.value(),exception);
        response.getWriter().print(convertObjectToJson(exceptionDto));
    }

    private void setResponse(HttpServletResponse response) {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
    }

    public String convertObjectToJson(Object object) throws JsonProcessingException {
        if (object == null) {
            return null;
        }
        return mapper.writeValueAsString(object);
    }

}
