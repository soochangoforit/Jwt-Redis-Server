package server.jwt.redis.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import server.jwt.redis.Redis.domain.LogoutToken;
import server.jwt.redis.Redis.service.LogoutTokenService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;


import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * SecurityConfig에서 정의한 권한이 필요한 요청은 해당 Filter를 거친다.
 * 권한이 필요없는 permitAll에 대해서는 해당 Filter를 거치지 않는다.
 */
@Component
public class CustomAuthorizationFilter extends BasicAuthenticationFilter {

    private final JwtProvider jwtProvider;
    private final LogoutTokenService logoutTokenService;

    /**
     * refresh 요청 및 일반 권한이 필요없는 요청은 해당 필터를 거치지 않는다.
     * 대신 config에 해당 url에 대해서는 반드시 permitAll()이 이루어져야 한다.
     * 권한이 필요없는 모든 요청을 여기다가 담아준다. 즉 PERMIT ALL에 해당하는 요청들
     */
//    private static final List<String> EXCLUDE_URL = List.of(
//            "/api/v1/user/refresh", "/api/v1/user/signup", "/api/v1/user/login", "/api/v1/user/home");

    @Value("${spring.jwt.blacklist.access-token}")
    private String blackListATPrefix;

    public CustomAuthorizationFilter(AuthenticationManager authenticationManager, JwtProvider jwtProvider, LogoutTokenService logoutTokenService) {
        super(authenticationManager);
        this.jwtProvider = jwtProvider;
        this.logoutTokenService = logoutTokenService;
    }


    /**
     * 접근 권한이 필요한 모든 요청이 들어온다. 권한이 필요없는 요청인 경우 EXCLUDE_URL에 의헤서 다음 filter로 넘어간다.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                                                throws IOException, ServletException {

            String accessToken = resolveToken(request.getHeader(AUTHORIZATION));

            if (accessToken != null) {
                // 사용하고자 하는 AccessToken이 Redis의 로그아웃된 AccessToken인지 아닌지 확인하는 절차
                LogoutToken isLogout = logoutTokenService.findLogoutToken(blackListATPrefix + accessToken);

                // 로그아웃되어 redis에 black list로 올라온 access token에 대해서는 접근이 불가능하다.
                if(isLogout != null){
                    // return 403 value
                    request.setAttribute("exception","로그아웃된 토큰입니다.");
                    filterChain.doFilter(request, response);
                }

                // 로그인시 black list에 access token이 없는 경우 들어간다.
                if(ObjectUtils.isEmpty(isLogout)){
                    // 토큰 유효성 검사 후 문제 없으면 spring security session에 해당 객체 저장
                    // validation 검사 후 문제 있으면 exception을 request에 set하고 다음 filter chain으로 넘어간다.
                    // 해당 exception에 대해서는 CustomAuthenticationEntryPoint에서 처리한다.
                    Authentication authentication = jwtProvider.validateToken(request, accessToken);
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    filterChain.doFilter(request, response);
                }

            } else {
                // 로그인에 필요한 서비스에 접근했는데 Header에 토큰이 없는 경우
                // todo : 주석 처리, 만약 BasicAuthenticationFilter로 통해서 인증이 필요한 부분에 대해 들어오는데
                // todo : 아무런 권한이 없으면 AccessDeinedHandler로 넘어가는지 확인 필요
                request.setAttribute("exception","로그인이 필요한 서비스입니다.");
                filterChain.doFilter(request, response);
            }
    }

    /**
     * Request Header에서 "Bearer "를 짤라내고 token만 가져온다.
     */
    private String resolveToken(String authorization) {
        return authorization != null ? authorization.substring(7) : null; // "bearer " 짤라낸다.
    }

    // Filter에서 제외할 URL 설정, 해당 method에 걸리는 path는 다음 filterChain으로 넘어간다.
//    @Override
//    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
//        return EXCLUDE_URL.stream().anyMatch(exclude -> exclude.equalsIgnoreCase(request.getServletPath()));
//    }
}
