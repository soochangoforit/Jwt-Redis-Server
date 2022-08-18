package server.jwt.redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import server.jwt.redis.domain.Member;
import server.jwt.redis.exception.BadRequestException;
import server.jwt.redis.repository.MemberRepository;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder passwordEncoder;

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







}
