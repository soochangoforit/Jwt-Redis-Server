package server.jwt.redis.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import server.jwt.redis.Redis.RedisValue;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${spring.jwt.blacklist.access-token}")
    private String blackListATPrefix;




    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                                                throws IOException, ServletException {

        // refresh 요청 및 일반 권한이 필요없는 요청은 해당 필터를 거치지 않는다.
        // 대신 config에 해당 url에 대해서는 반드시 permitAll()이 이루어져야 한다.
        // 권한이 필요없는 모든 요청을 여기다가 담아준다. 즉 PERMIT ALL에 해당하는 요청들
        if (request.getServletPath().equals("/api/v1/user/refresh") || request.getServletPath().equals("/api/v1/user/login")
        || request.getServletPath().equals("/api/v1/user/signup") || request.getServletPath().equals("/api/v1/user/home") ) {
            filterChain.doFilter(request, response);
        }else{
            String accessToken = resolveToken(request.getHeader(AUTHORIZATION));

            // 일반 로그인, 회원가입 같은 경우는 header가 없기 때문에 그냥 다음 filter로 넘어간다.
            if (accessToken != null) {
                // todo : test 필요
                // 사용하고자 하는 AccessToken이 Redis의 로그아웃된 AccessToken인지 아닌지 확인하는 절차
                RedisValue isLogout = (RedisValue) redisTemplate.opsForValue().get(blackListATPrefix + accessToken);

                if(isLogout != null){
                    request.setAttribute("exception","로그아웃된 토큰 입니다.");
                    filterChain.doFilter(request, response);
                }

                // 로그인시 black list에 access token이 없는 경우 들어간다.
                if(ObjectUtils.isEmpty(isLogout)){
                    // 토큰 유효성 검사 후 문제 없으면 spring security session에 해당 객체 저장
                    // validation 검사 후 문제 있으면 exception을 request에 set하고 다음 filter chain으로 넘어간다.
                    // 해당 exception에 대한 entry point 필요
                    Authentication authentication = jwtProvider.validateToken(request, accessToken);
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    filterChain.doFilter(request, response);
                }

            } else {
                filterChain.doFilter(request, response);
            }
        }


    }

    /**
     * Request Header에서 "Bearer "를 짤라내고 token만 가져온다.
     */
    private String resolveToken(String authorization) {
        return authorization != null ? authorization.substring(7) : null; // "bearer " 짤라낸다.
    }




}
