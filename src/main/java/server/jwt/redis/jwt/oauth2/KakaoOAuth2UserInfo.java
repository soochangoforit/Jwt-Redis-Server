package server.jwt.redis.jwt.oauth2;

import java.util.Map;

public class KakaoOAuth2UserInfo extends OAuth2UserInfo{

    private Map<String, Object> kakao_account = (Map<String, Object>) attributes.get("kakao_account");

    private Map<String, Object> profile = (Map<String, Object>) kakao_account.get("profile");


    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id").toString();
    }

    @Override
    public String getName() {
        return (String) profile.get("nickname");
    }

    @Override
    public String getEmail() {
        return (String) kakao_account.get("email");
    }

    @Override
    public String getImageUrl() {
        return profile.get("profile_image_url").toString();
    }
}
