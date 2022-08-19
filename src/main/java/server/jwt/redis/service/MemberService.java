package server.jwt.redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import server.jwt.redis.domain.Member;
import server.jwt.redis.dto.response.LoginResponseDto;
import server.jwt.redis.exception.BadRequestException;
import server.jwt.redis.jwt.JwtProvider;
import server.jwt.redis.repository.MemberRepository;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    /**
     * 회원가입 시나리오는 다음과 같다.
     *
     * 이메일 중복 체크
     * 비밀번호 규칙 체크
     * 비밀번호 해시
     * 회원가입
     */
    @Transactional
    public void signUp(String email, String nickname, String password){
        checkEmailIsDuplicate(email);
        //checkPasswordConvertion(password); 비밀번호 규칙 설정
        String encodedPassword = passwordEncoder.encode(password);
        Member newAccount = Member.of(email, nickname, encodedPassword);
        memberRepository.save(newAccount);
    }

    private void checkEmailIsDuplicate(String email) {
        boolean isDuplicate = memberRepository.existsByEmail(email);
        if(isDuplicate) {
            throw new BadRequestException("이미 존재하는 회원입니다.");
        }
    }


    /**
     * 추가로, 기존에는 jwtProvider의 createToken 메서드를 호출하여 AccessToken을 발급하였으나
     * RefreshToken의 발급 또한 비슷한 과정을 통해 발급되기 때문에 재사용성을 고려하여 아래와 같이 수정하였다.
     */
    public LoginResponseDto login(String email, String password) {
        Member member = memberRepository.findByEmail(email).orElseThrow(() -> new BadRequestException("아이디 혹은 비밀번호를 확인하세요."));
        checkPassword(password, member.getPassword());

        String accessToken = jwtProvider.createAccessToken( member.getId().toString(), member.getEmail(), member.getRole());
        String refreshToken = jwtProvider.createRefreshToken(member.getId().toString(), member.getEmail(), member.getRole());

        return new LoginResponseDto(accessToken, refreshToken);
    }

    private void checkPassword(String password, String encodedPassword) {
        boolean isSame = passwordEncoder.matches(password, encodedPassword);
        if(!isSame) {
            throw new BadRequestException("아이디 혹은 비밀번호를 확인하세요.");
        }
    }


    public LoginResponseDto reIssueAccessToken(String email, String refreshToken) {
        Member member = memberRepository.findByEmail(email).orElseThrow(() -> new BadRequestException("존재하지 않는 유저입니다."));
        // refresh token이 redis이 존재하는지 확인 -> 존재하면 유효한 토큰이므로 발급
        jwtProvider.checkRefreshToken(member.getId(), refreshToken);
        String accessToken = jwtProvider.createAccessToken(member.getId().toString(),member.getEmail(), member.getRole());
        return new LoginResponseDto(accessToken, refreshToken);

    }
}
