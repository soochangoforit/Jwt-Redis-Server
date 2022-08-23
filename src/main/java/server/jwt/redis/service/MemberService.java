package server.jwt.redis.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import server.jwt.redis.Redis.RedisService;
import server.jwt.redis.domain.Member;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.dto.response.LoginResponseDto;
import server.jwt.redis.exception.BadRequestException;
import server.jwt.redis.jwt.JwtProvider;
import server.jwt.redis.repository.MemberRepository;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final DuplicateService duplicateService;
    private final RedisService redisService;

    /**
     * 회원가입 시나리오는 다음과 같다.
     *
     * 이메일 중복 체크
     * 비밀번호 규칙 체크
     * 비밀번호 해시
     * 회원가입
     */
    @Transactional
    public void signUp(String username, String password , String email , String nickname) {
        duplicateService.checkMemberIsDuplicate(username,email,nickname);
        duplicateService.checkPasswordConversion(password);
        String encodedPassword = passwordEncoder.encode(password);
        Member newAccount = Member.of(username, encodedPassword, email, nickname , Role.ROLE_USER);
        memberRepository.save(newAccount);
    }


    public Map<String, String> reIssueAccessToken(String refreshToken, String clientIp) {

        // 유효성 검증이 어차피 존재하지 않는 refresh token이면 redis에서 걸러주지만 먼저 걸러주는 작업을 해보도록 하자
        // refresh token에 문제가 있으면 Exception을 반환한다.
        jwtProvider.validateRefreshToken(refreshToken);

        // refresh token이 redis이 존재하는지 확인 -> 존재하면 유효한 토큰이므로 발급
        // todo : test 필요 다른 ip에서
        Map<String, String> redisValueMap = jwtProvider.checkRefreshToken(refreshToken, clientIp);

        // 올바른 요청이든 , 그렇지 않든 무조건 일단 삭제한다.
        redisService.deleteRefreshToken(refreshToken);

        // 유효하면 Availability true, 유효하지 않으면 false
        String newAccessToken = null;
        String newRefreshToken = null;
        if(redisValueMap != null) {
            String userId = redisValueMap.get("userId");
            newAccessToken = jwtProvider.createAccessToken(Long.parseLong(userId), Role.ROLE_USER);
            newRefreshToken = jwtProvider.createRefreshToken(Long.parseLong(userId), clientIp);
        }else{
            throw new BadRequestException("해킹이 의심되거나 혹은 refresh token을 요청한 IP주소가 달라졌습니다.");
        }

        Map<String, String> map = new HashMap<>();
        map.put("accessToken", newAccessToken);
        map.put("refreshToken", newRefreshToken);


        return map;
    }


    public void logout(String accessToken, String refreshToken) {
        jwtProvider.logout(accessToken, refreshToken);

    }
}
