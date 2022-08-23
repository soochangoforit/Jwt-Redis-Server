package server.jwt.redis.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import server.jwt.redis.domain.Member;
import server.jwt.redis.dto.request.LoginRequestDto;
import server.jwt.redis.dto.response.DefaultDataResponse;
import server.jwt.redis.dto.response.LoginResponseDto;
import server.jwt.redis.service.RequestService;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final CustomAuthenticationManager customAuthenticationManager;
    private final JwtProvider jwtProvider;
    private final RequestService requestService;





    // /login post 요청이 올때 해당 메소드를 우선적으로 거친다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 아이디 : username
        // 비밀번호 : password

        // 사용자가 입력했던 로그인 아이디, 비밀번호를 JSON형태로 받아서 갖는다.
        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequestDto loginRequestDto;
        try {
            loginRequestDto = objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String clientIp = requestService.getClientIp(request);
        request.setAttribute("clientIp", clientIp);

        // authenticate 메소드의 파리미터 값이 Authentication를 요구하고 있기 때문에, 해당 하위 클래스로 감싸준다.
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());

        return customAuthenticationManager.authenticate(authenticationToken);
    }

    // attemptAuthentication 메소드가 완전히 끝난후 , 로그인에 성공한 경우 바로 처리되는 메소드
    // 로그인에 성공했기 때문에, access , refresh token을 만들어줘서 반환한다. 아직까지는 Spring Context Holder에 사용자 정보를 저장하지 않는다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException {


        String clientIp = (String) request.getAttribute("clientIp");

        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        Member member = principal.getMember();

        String accessToken = jwtProvider.createAccessToken( member.getId(), member.getRole());
        String refreshToken = jwtProvider.createRefreshToken(member.getId() ,clientIp);

        // refresh token은 cookie에 담아주기
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .maxAge(1 * 24 * 60 * 60) // 1 day
                .httpOnly(true)
                .path("/")
                .build();

        response.setHeader("Set-Cookie",cookie.toString());

        LoginResponseDto responseDto = new LoginResponseDto(accessToken);

        // 응답시 정해진 형식에 맞춰서 응답, status, message , data를 담아서 응답한다.
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setCharacterEncoding("UTF-8");

        DefaultDataResponse<LoginResponseDto> loginSuccessResponse = DefaultDataResponse.of(HttpStatus.OK.value(), "로그인 성공", responseDto);
        response.getWriter().write(new ObjectMapper().writeValueAsString(loginSuccessResponse));
    }
}
