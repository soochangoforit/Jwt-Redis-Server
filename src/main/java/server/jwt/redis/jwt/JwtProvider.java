package server.jwt.redis.jwt;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import server.jwt.redis.Redis.RedisService;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.exception.BadRequestException;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtProvider {
    @Value("${spring.jwt.secret-key}")
    private String secretKey;
    private static final Long TOKEN_VALID_TIME = 1000L * 60 * 3; // 3mins access token 유효시간

    private final PrincipalDetailsService principalDetailsService;
    private final RedisService redisService;

    // 의존성 주입 후, 초기화를 수행
    // 객체 초기화, secretKey Base64로 인코딩한다.
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }


    public String createAccessToken(String userId, String email ,Role role) {
        Long tokenInvalidTime = 1000L * 60 * 3; // 3mins
        return this.createToken(userId,  email ,role ,tokenInvalidTime);
    }

    public String createRefreshToken(String userId, String email , Role role) {
        Long tokenInvalidTime = 1000L * 60 * 60 * 24; // 1day
        String refreshToken = this.createToken(userId, email, role, tokenInvalidTime);
        redisService.setValues(userId, refreshToken, Duration.ofMillis(tokenInvalidTime)); // redis에서 기간도 함께 설정
        return refreshToken;
    }



    private String createToken(String userId, String email, Role role , Long tokenInvalidTime){
        Claims claims = Jwts.claims().setSubject(userId); // claims 생성 및 payload 설정
        claims.put("email",email);
        claims.put("roles", role.getAuthority()); // 권한 설정, key/ value 쌍으로 저장
        Date date = new Date();

        return Jwts.builder()
                .setClaims(claims) // 발행 유저 정보 저장
                .setIssuedAt(date) // 발행 시간 저장
                .setExpiration(new Date(date.getTime() + tokenInvalidTime)) // 토큰 유효 시간 저장
                .signWith(SignatureAlgorithm.HS256, secretKey) // 해싱 알고리즘 및 키 설정
                .compact(); // 생성
    }

    /**
     * validateToken
     * 토큰을 검증하는 메서드이며 토큰이 유효하지 않다면 해당되는 에러메세지를 추가하여
     * CustomAuthenticationEntryPoint로 넘어가며 예외처리된다.
     */
    public Authentication validateToken(HttpServletRequest request, String token) {
        String exception = "exception";
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return getAuthentication(token);
        } catch (MalformedJwtException | SignatureException | UnsupportedJwtException e) {
            request.setAttribute(exception, "토큰의 형식을 확인하세요");
        } catch (ExpiredJwtException e) {
            request.setAttribute(exception, "토큰이 만료되었습니다.");
        } catch (IllegalArgumentException e) {
            request.setAttribute(exception, "JWT compact of handler are invalid");
        }
        return null;
    }

    private Authentication getAuthentication(String token) {
        PrincipalDetails principalDetails = (PrincipalDetails) principalDetailsService.loadUserByUsername(getUserEmail(token));
        return new UsernamePasswordAuthenticationToken(principalDetails, "", principalDetails.getAuthorities());
    }

    private String getUserEmail(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("email").toString(); // 고유 id가 나온다.
    }

    public void checkRefreshToken(Long userId, String refreshToken) {
        String redisRT = redisService.getValues(userId.toString());
        //refresh token이 redis에 존재하지 않는 경우, 토큰이 만료되어서 redis에서 사라진 경우
        if (!refreshToken.equals(redisRT)) {
            throw new BadRequestException("토큰이 만료되었습니다.");
        }
    }



}
