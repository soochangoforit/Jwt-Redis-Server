package server.jwt.redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import server.jwt.redis.exception.BadRequestException;
import server.jwt.redis.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class DuplicateService {

    private final MemberRepository memberRepository;


    /**
     *  전체 duplicate check method
     */
    public void checkMemberIsDuplicate(String username, String email, String nickname) {
        boolean isDuplicate = memberRepository.existsByUsernameAndEmailAndNickname(username,email,nickname);
        if(isDuplicate) {
            throw new BadRequestException("이미 존재하는 회원입니다.");
        }
    }

    /**
     * password pattern check method
     */
    public void checkPasswordConversion(String password) {
        //use regular expression "(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"
        if(!password.matches("(?=.*[a-zA-Z])(?=.*[0-9]).{8,}")) {
            throw new BadRequestException("비밀번호는 영문자 대*소문자와 숫자를 혼합하여 8자 이상 사용해야 합니다.");
        }
    }

    /**
     * check username duplicate method
     */
    public void checkUsernameIsDuplicate(String username) {
        boolean isDuplicate = memberRepository.existsByUsername(username);
        if(isDuplicate) {
            throw new BadRequestException("이미 존재하는 아이디입니다.");
        }
    }

    /**
     * check email duplicate method
     */
    public void checkEmailIsDuplicate(String email) {
        boolean isDuplicate = memberRepository.existsByEmail(email);
        if(isDuplicate) {
            throw new BadRequestException("이미 존재하는 이메일입니다.");
        }
    }

    /**
     * check nickname duplicate method
     */
    public void checkNicknameIsDuplicate(String nickname) {
        boolean isDuplicate = memberRepository.existsByNickname(nickname);
        if(isDuplicate) {
            throw new BadRequestException("이미 존재하는 닉네임입니다.");
        }
    }


}
