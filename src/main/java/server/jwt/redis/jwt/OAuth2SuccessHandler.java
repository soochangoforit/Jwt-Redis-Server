package server.jwt.redis.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import server.jwt.redis.domain.Member;
import server.jwt.redis.dto.response.DefaultDataResponse;
import server.jwt.redis.dto.response.LoginResponseDto;
import server.jwt.redis.service.RequestService;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final RequestService requestService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        PrincipalDetails principalDetail = (PrincipalDetails) authentication.getPrincipal();
        Member member = principalDetail.getMember();

        String access_token = jwtProvider.createAccessToken(member.getId() , member.getRole());
        String refresh_token = jwtProvider.createRefreshTokenWithLogin(member.getId() ,requestService.getClientIp(request));

        // refresh token은 cookie에 담아주기
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refresh_token)
                .maxAge(1 * 24 * 60 * 60) // 1 day
                .httpOnly(true)
                .path("/")
                .build();

        response.setHeader("Set-Cookie",cookie.toString());

        LoginResponseDto responseDto = new LoginResponseDto(access_token);

        // 응답시 정해진 형식에 맞춰서 응답, status, message , data를 담아서 응답한다.
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setCharacterEncoding("UTF-8");

        DefaultDataResponse<LoginResponseDto> loginSuccessResponse = DefaultDataResponse.of(HttpStatus.OK.value(), "로그인 성공", responseDto);
        response.getWriter().write(new ObjectMapper().writeValueAsString(loginSuccessResponse));

    }
}
