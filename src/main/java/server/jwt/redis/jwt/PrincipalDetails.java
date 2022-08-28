package server.jwt.redis.jwt;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import server.jwt.redis.domain.Member;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Getter
public class PrincipalDetails implements UserDetails , OAuth2User {

    private final Member member;

    private Map<String ,Object> attributes;

    public PrincipalDetails(Member member) {
        this.member = member;
    }

    // Oauth2
    public PrincipalDetails(Member member,Map<String, Object> attributes) { // OAuth2 로그인용 생성지
        this.member = member;
        this.attributes = attributes;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> authorities = new ArrayList<>();

        authorities.add(new SimpleGrantedAuthority(member.getRole().getAuthority()));

        return authorities;
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getUsername();
    }

    // oauth2
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // oauth2
    @Override
    public String getName() {
        return member.getName();
    }



    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


}
