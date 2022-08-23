package server.jwt.redis.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import server.jwt.redis.domain.Member;
import server.jwt.redis.exception.BadRequestException;
import server.jwt.redis.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;


    @Override
    public UserDetails loadUserByUsername(String username) {
        Member member = memberRepository.findByUsername(username).orElseThrow(() -> new AuthenticationException("아이디 혹은 비밀번호를 확인하세요.") {
        });
        return new PrincipalDetails(member);
    }
}
