package server.jwt.redis.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import server.jwt.redis.domain.Member;
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
        String ip = requestService.getClientIp(request);
        String refresh_token = jwtProvider.createRefreshToken(member.getId() ,requestService.getClientIp(request));


        Map<String , String> tokens = new HashMap<>();
        tokens.put("access_token" , access_token);
        tokens.put("refresh_token" , refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(new ObjectMapper().writeValueAsString(tokens)); // that's going to return everything in the body

        //new ObjectMapper().writeValue(response.getOutputStream(), tokens); // that's going to return everything in the body

    }
}
