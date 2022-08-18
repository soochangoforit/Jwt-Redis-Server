package server.jwt.redis.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 기본적으로 Filter로 수행되는 것은 Form기반의 아이디와 비밀번호로 진행되는 UsernamePasswordAuthenticationFilter가 수행된다.
 *
 * 하지만 JWT 인증을 위해서는 새로운 필터를 만들어 UsernamePasswordAuthenticationFilter보다 먼저 수행되게 설정해야 한다.
 *
 * 모든 요청이 해당 필터를 우선적으로 거치게 된다.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    /**
     * Authorization이 Header에 없다면 다음 filter chain으로 넘어간다.
     *
     * 일반적인 로그인 혹은 회원가입 하는 경우
     *
     * 주된 역할을 해당 요청에서 access 토큰을 가져와서 유효성 검사를 하고 문제 없으면
     * spring security contextHolder에 유저 정보를 넣고 다음 체인 이동
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(request.getHeader("Authorization"));
        if (token != null) {
            // 토큰 유효성 검사 후 문제 없으면 spring security session에 해당 객체 저장
            // validation 검사 후 문제 있으면 exception을 request에 set하고 다음 filter chain으로 넘어간다.
            // 해당 exception에 대한 entry point 필요
            Authentication authentication = jwtProvider.validateToken(request, token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Request Header에서 "Bearer "를 짤라내고 token만 가져온다.
     */
    private String resolveToken(String authorization) {
        return authorization != null ? authorization.substring(7) : null; // "bearer " 짤라낸다.
    }




}
