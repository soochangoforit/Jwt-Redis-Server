package server.jwt.redis.jwt;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import server.jwt.redis.Redis.RedisService;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.repository.MemberRepository;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.*;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtProvider {
    @Value("${spring.jwt.secret-key}")
    private String secretKey;
    private final PrincipalDetailsService principalDetailsService;
    private final RedisService redisService;

    private final MemberRepository memberRepository;

    @Value("${spring.jwt.blacklist.access-token}")
    private String blackListATPrefix;


    // 의존성 주입 후, 초기화를 수행
    // 객체 초기화, secretKey Base64로 인코딩한다.
    // 기존 생성자 이후 실행된다.
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }


    public String createAccessToken(Long userId,Role role) {
        Long tokenInvalidTime = 1000L * 60 * 30; // 30mins
        return this.createTokenForAccess(userId,role ,tokenInvalidTime);
    }

    public String createRefreshToken(Long userId, String clientIp) {
        Long tokenInvalidTime = 1000L * 60 * 60 * 24; // 1day
        String refreshToken = this.createTokenForRefresh(tokenInvalidTime);
        redisService.setRefreshValues(refreshToken, clientIp , userId, Duration.ofMillis(tokenInvalidTime)); // redis에서 기간도 함께 설정
        return refreshToken;
    }



    private String createTokenForAccess(Long userId, Role role , Long tokenInvalidTime){
        Claims claims = Jwts.claims().setSubject(userId.toString()); // claims 생성 및 payload 설정
        claims.put("role", role.getAuthority()); // 권한 설정, key/ value 쌍으로 저장
        Date date = new Date();

        return Jwts.builder()
                .setClaims(claims) // 발행 유저 정보 저장
                .setIssuedAt(date) // 발행 시간 저장
                .setExpiration(new Date(date.getTime() + tokenInvalidTime)) // 토큰 유효 시간 저장
                .signWith(SignatureAlgorithm.HS256, secretKey) // 해싱 알고리즘 및 키 설정
                .compact(); // 생성
    }


    private String createTokenForRefresh(Long tokenInvalidTime){
        //Claims claims = Jwts.claims().setSubject(userId.toString()); // claims 생성 및 payload 설정
        Date date = new Date();

        return Jwts.builder()
                //.setClaims(claims) // 발행 유저 정보 저장
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
    public Authentication validateToken(HttpServletRequest request, String accessToken) {
        String exception = "exception";
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(accessToken); //verify token

            return new UsernamePasswordAuthenticationToken(getDb_Id(accessToken),"",getRole(accessToken));
        } catch (MalformedJwtException | SignatureException | UnsupportedJwtException e) {
            request.setAttribute(exception, "토큰의 형식을 확인하세요");
        } catch (ExpiredJwtException e) {
            request.setAttribute(exception, "토큰이 만료되었습니다.");
        } catch (IllegalArgumentException e) {
            request.setAttribute(exception, "JWT claims string is empty.");
        }
        return null;
    }

    /**
     * refresh token을 재발급 하기전 token 유효성검사 실시
     */
    public void validateRefreshToken(String refreshToken) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(refreshToken); //verify token
        } catch (MalformedJwtException | SignatureException | UnsupportedJwtException e) {
            throw new BadCredentialsException("Refresh 토큰의 형식을 확인하세요");
        } catch (ExpiredJwtException e) {
            throw new BadCredentialsException("Refresh 토큰이 만료되었습니다.");
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Refresh JWT compact of handler are invalid");
        }
    }



    /**
     * AccessToken에 있는 정보가지고 다시 DB를 조회해서 존재하는 회원인지 확인하는 과정은 생략하기 위해
     * 너무 많은 요청이 오면, 분명 성능저하 발생
     * 그리고 spring security context holder에는 필요한 정보만 담기 위해서 (고유 Db_id)
     */
    public String getDb_Id(String token) {
        String db_id = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
        return db_id;
    }

    private Collection<GrantedAuthority> getRole(String token) {
        String role = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("role", String.class);

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(role));

        return authorities;
    }


    public Map<String, String> checkRefreshToken(String refreshToken, String clientIp) {

        Map<String, String> valuesFromRedis = redisService.getValuesForClientIp(refreshToken);
        // 첫요청한 refresh token이 아직 유효하면서도 올바른 요청의 ip인 경우
        // 탈취 된 token 혹은 이전에 요청한 ip가 아닌 경우
        if(valuesFromRedis.get("realClientIp").equals(clientIp)){
            return valuesFromRedis;
        }
        return null;
    }

    public void logout(String accessToken, String refreshToken){
        // 로그아웃 하려는 사용자의 refresh token 을 redis에서 삭제한다.
        redisService.deleteRefreshToken(refreshToken);

        Long expiration = getExpiration(accessToken);

        redisService.setLogoutAccessValues(blackListATPrefix + accessToken,
                "logout", Duration.ofMillis(expiration));

    }

    public Long getExpiration(String accessToken) {
        // accessToken 남은 유효시간
        Date expiration = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(accessToken).getBody().getExpiration();
        // 현재 시간
        long now = new Date().getTime();
        return (expiration.getTime() - now);
    }




}
