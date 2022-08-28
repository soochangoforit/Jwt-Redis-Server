package server.jwt.redis.jwt.oauth2;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import server.jwt.redis.domain.Member;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.exception.OAuth2AuthenticationProcessingException;
import server.jwt.redis.jwt.PrincipalDetails;
import server.jwt.redis.repository.MemberRepository;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }


    @Transactional
    public OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {

        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes);

        if(oAuth2UserInfo.getId().isEmpty()) {
            throw new OAuth2AuthenticationProcessingException("social id not found from OAuth2 provider");
        }

        Optional<Member> memberOptional = memberRepository.findByUsername(oAuth2UserInfo.getId()); // 고유 번호를 아이디로 판단
        Member member;
        if(memberOptional.isPresent()) {
            member = memberOptional.get();
            // oauth2 로그인도 일종의 회원가입이기 떄문에 사용자는 원래 계정에 접속하기 위해서는 원래 로그인 했던 소셜로그인을 진행해야한다.
            if(!member.getProvider().equals(oAuth2UserRequest.getClientRegistration().getRegistrationId())) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        member.getProvider() + " account. Please use your " + member.getProvider() +
                        " account to login.");
            }
            // oauth2에서 name, email, picture를 바꾸면 알아서 업데이트 된다.
           member = updateExistingUser(member, oAuth2UserInfo);

        } else {
            member = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        return new PrincipalDetails(member, oAuth2User.getAttributes());
    }


    public Member updateExistingUser(Member existingMember, OAuth2UserInfo oAuth2UserInfo) {
        Member member = existingMember.updatedByOAuth2(oAuth2UserInfo);
        memberRepository.save(member);
        return member;
    }


    public Member registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
      Member member = Member.builder()
                    .username(oAuth2UserInfo.getId())
                    .name(oAuth2UserInfo.getName())
                    .email(oAuth2UserInfo.getEmail())
                    .password(bCryptPasswordEncoder.encode(oAuth2UserInfo.getId()))
                    .picture(oAuth2UserInfo.getImageUrl())
                    .role(Role.ROLE_USER)
                    .provider(oAuth2UserRequest.getClientRegistration().getRegistrationId())
                    .build();
        return memberRepository.save(member);
    }

}
