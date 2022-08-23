package server.jwt.redis.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import server.jwt.redis.exception.BadRequestException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {

    private final PrincipalDetailsService principalDetailsService;


    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        final PrincipalDetails principalDetails =
                (PrincipalDetails) principalDetailsService.loadUserByUsername(authentication.getName());

        if (!bCryptPasswordEncoder.matches(authentication.getCredentials().toString(), principalDetails.getPassword())) {
            throw new AuthenticationException("비밀번호를 확인하세요"){};
        }

        return new UsernamePasswordAuthenticationToken(principalDetails, principalDetails.getPassword(), principalDetails.getAuthorities());

    }


}
