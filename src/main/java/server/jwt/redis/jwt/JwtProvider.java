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
import server.jwt.redis.exception.DuplicateException;
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

    public String createRefreshTokenWithLogin(Long userId, String clientIp) {
        Long tokenInvalidTime = 1000L * 60 * 60 * 24; // 1day
        String refreshToken = this.createTokenForRefresh(tokenInvalidTime);

        // todo : 우선적으로 userID를 key값으로 해서 refresh token이 있는지 확인하는 작업 필요
        String oldToken = redisService.findTokenByUserId(userId);

        // todo : key값으로 userID가 없다는 말은 최초 로그인 의미 -> 바로 userID를 key 값, 처음으로 만든 refresh token을 value 값으로 저장한다.
        // todo : refresh token을 key값으로 하는 작업도 필요하다.
        if(oldToken == null) {
            redisService.setUserIdWithRefreshToken(userId, refreshToken , Duration.ofMillis(tokenInvalidTime));
            redisService.setRefreshValues(refreshToken, clientIp , userId, Duration.ofMillis(tokenInvalidTime));
        }else{
            // todo : oldToken이 존재하면 그것이 곧 앞전의 토큰이다.
            redisService.deleteRefreshToken(oldToken);
            // todo : oldToken을 다시 key 값으로 하는 Message 큐를 만든다. -> refresh token의 기존 유효시간과 같게 한다. -> 나중에 oldRefresh Token으로 재발급을 요청해도 유효기간 지나면 쓸모 없어지기 때문에 앞단에서 유효성 검사를 통해서 걸러진다.
            redisService.setOldTokenToMessageQueue(oldToken , "duplicate", Duration.ofMillis(tokenInvalidTime));

            redisService.setUserIdWithRefreshToken(userId, refreshToken , Duration.ofMillis(tokenInvalidTime));
            redisService.setRefreshValues(refreshToken, clientIp , userId, Duration.ofMillis(tokenInvalidTime));
        }


        // todo : key값으로 userId가 존재한다. -> 앞전에 로그인한 흔적이 있다는 의미 (redis에 남아 있다는 의미는 중복 로그인이며, 아직토큰이 유효하다.)
        // todo : userId에 해당하는 refresh token을 찾는다. -> 완료 -> oldToken
        // todo : refresh token을 key값으로 하는 데이터를 삭제한다. -> 완료
        // todo : userId를 key 값으로 하는 데이터에 new refresh token을 저장한다. -> 완료
        // todo : new refresh token을 key 값으로 하는 데이터를 추가한다.

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


    public Map<String, String> checkRefreshToken(String oldRefreshToken, String clientIp) {

        // todo : 우선적으로 oldRefreshToken을 가지고 "중복" redis에 존재하는지 확인한다.
        String isDuplicate = redisService.findOldTokenFromDuplicate(oldRefreshToken);

        if(isDuplicate != null && isDuplicate.equals("duplicate")) {
            // todo : 존재 O -> "duplicate" 라는 메시지가 담기는 경우 -> 중복 로그인에 의해서 발생 -> 중복 로그인 시점부터 refresh token lify cycle만큼 유요하게 redis에 저장되어 있다.
            throw new DuplicateException("토큰 재발급에 앞서, 중복 로그인이 감지 되었습니다.");
        }else{
            // todo : 존재 O -> clietIp 와 userId로 데이터가 구성된 경우 -> 중복 로그인은 발생하지 X
            Map<String, String> valuesFromRedis = redisService.getValuesForClientIp(oldRefreshToken);
            // 첫요청한 refresh token이 아직 유효하면서도 올바른 요청의 ip인 경우
            // 탈취 된 token 혹은 이전에 요청한 ip가 아닌 경우
            if(valuesFromRedis.get("realClientIp").equals(clientIp)){
                return valuesFromRedis;
            }
            return null;
        }
    }

    public void logout(String accessToken, String refreshToken){
        // 로그아웃 하려는 사용자의 refresh token 을 redis에서 삭제한다.
        redisService.deleteRefreshToken(refreshToken);

        // 로그아웃시 access token의 id를 가져와서 삭제를 진행
        String userId = this.getDb_Id(accessToken); // db_id
        redisService.deleteByUserId(userId);

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


    public String createRefreshTokenWithReissue(Long userId, String clientIp) {
        Long tokenInvalidTime = 1000L * 60 * 60 * 24; // 1day
        String newRefreshToken = this.createTokenForRefresh(tokenInvalidTime); // new refresh token 재발급

        redisService.setUserIdWithRefreshToken(userId, newRefreshToken, Duration.ofMillis(tokenInvalidTime)); // UserId에 덮어쓰기
        redisService.setRefreshValues(newRefreshToken, clientIp, userId, Duration.ofMillis(tokenInvalidTime));

        return newRefreshToken;
    }
}
