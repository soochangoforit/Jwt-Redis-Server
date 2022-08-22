package server.jwt.redis.jwt;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import server.jwt.redis.domain.Member;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.repository.MemberRepository;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2 = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // google or kakao ..

        // todo : registrationId가 있는지 ㅇ벗는지 확인한느 코드 필요 , 없음녀 error 반환

        // 보통은 sub , id 가 나오지만 naver 같은 경우는 response가 담긴다.
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(); // 로그인한 사용자의 정보모음 // sub , email , id <-> naver:response

        // 소셜 로그인에 성공한 사용자의 정보들이 map 으로 담겨있다.
        OAuth2Attribute oAuth2Attribute =
                OAuth2Attribute.of(registrationId, userNameAttributeName, oAuth2.getAttributes());


        log.info("{}", oAuth2Attribute);

        // id, provider, name, email, picutre
        // 각 소셜에 맞는 키 값이 알아서 맞춰서 나온다. -> 소셜마다 제공하는 데이터에 대한 key 값이 달라져서..
        Map<String, Object> MemberAttributes = oAuth2Attribute.convertToMap();

        //naver gave us response , so we need to search more for user info
        String key_login = "";
        if (MemberAttributes.get("provider") == "naver"){
            Map<String , String> response = (Map<String, String>) oAuth2Attribute.getAttributes().get("response");
            key_login = response.get("id");
        }else{

            key_login = oAuth2Attribute.getAttributes().get(MemberAttributes.get("startPoint").toString()).toString();
        }

        String loginId = String.format("%s_%s", MemberAttributes.get("provider"),key_login);// todo : 이부분 변경 oauth2 -> oAuth2Attribute

        Optional<Member> memberOptional = memberRepository.findByUsername(loginId);

        Member saved = null;

        if(memberOptional.isEmpty()){
            // 한번도 소셜 로그인을 하지 않은 사용자이기 때문에, 강제 회원가입을 진행
            Member member = Member.builder()
                    .nickname(MemberAttributes.get("name").toString())
                    .username(loginId)
                    .email(MemberAttributes.get("email").toString())
                    .picture(MemberAttributes.get("picture").toString())
                    .password(bCryptPasswordEncoder.encode(loginId))
                    .role(Role.ROLE_USER)
                    .build();

            saved = memberRepository.save(member);

        }else{
            // 이미 회원가입 되어 있다.
            saved = memberOptional.get();

        }

        // return OAuth2User()
        return new PrincipalDetails(saved, oAuth2.getAttributes()); // 중요함

    }
}

@ToString
@Builder(access = AccessLevel.PRIVATE)
@Getter
class OAuth2Attribute {

    private Map<String, Object> attributes;
    private String attributeKey; // google : sub / naver : response / kakao : id
    private String provider;
    private String email;
    private String name;
    private String picture;

    static OAuth2Attribute of(String provider, String attributeKey,
                              Map<String, Object> attributes) {
        switch (provider) {
            case "google":
                return ofGoogle(attributeKey, attributes);
            case "kakao":
                return ofKakao("email", attributes);
            case "naver":
                return ofNaver("id", attributes);
            default:
                throw new RuntimeException();
        }
    }

    private static OAuth2Attribute ofGoogle(String attributeKey,
                                            Map<String, Object> attributes) { // attributeKey 파라미터로 sub이 온다.
        return OAuth2Attribute.builder()
                .provider("google")
                .name((String) attributes.get("name"))
                .email((String) attributes.get("email"))
                .picture((String)attributes.get("picture"))
                .attributes(attributes)
                .attributeKey(attributeKey) // "sub" :  숫자로 이루어진 긴 문자열
                .build();
    }

    private static OAuth2Attribute ofKakao(String attributeKey,
                                           Map<String, Object> attributes) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> kakaoProfile = (Map<String, Object>) kakaoAccount.get("profile");

        return OAuth2Attribute.builder()
                .provider("kakao")
                .name((String) kakaoProfile.get("nickname"))
                .email((String) kakaoAccount.get("email"))
                .picture((String)kakaoProfile.get("profile_image_url"))
                .attributes(kakaoAccount)
                .attributeKey(attributeKey)
                .build();
    }

    private static OAuth2Attribute ofNaver(String attributeKey,
                                           Map<String, Object> attributes) { // attributeKey에 'id'가 담긴다.
       Map<String, Object> response = (Map<String, Object>) attributes.get("response");
//
//        return OAuth2Attribute.builder()
//                .provider("naver")
//                .name((String) response.get("name"))
//                .email((String) response.get("email"))
//                .picture((String) response.get("profile_image"))
//                .attributes(response)
//                .attributeKey(attributeKey)
//                .build();


        return OAuth2Attribute.builder()
                .provider("naver")
                .name((String) response.get("name"))
                .email((String) response.get("email"))
                .picture((String) response.get("profile_image"))
                .attributes(attributes)
                .attributeKey(attributeKey)
                .build();

    }

    Map<String, Object> convertToMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("startPoint", attributeKey); // naver 같은 경우는 id
        map.put("provider", provider);
        map.put("name", name);
        map.put("email", email);
        map.put("picture", picture);

        return map;
    }
}