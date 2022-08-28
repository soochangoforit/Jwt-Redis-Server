package server.jwt.redis.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.jwt.oauth2.OAuth2UserInfo;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor
@Table(uniqueConstraints = {@UniqueConstraint( name="member_username" , columnNames = {"username"})})
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String name;


    @Column
    private String picture;

    @Enumerated(EnumType.STRING)
    private Role role;

    private String provider; // google, naver ,kakao


    @Builder
    private Member(String username, String password, String email, String name, String picture ,Role role, String provider) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.name = name;
        this.picture = picture;
        this.role = role;
        this.provider = provider;
    }

    public static Member of(String username, String password, String email, String name, Role role) {
        return Member.builder()
                .username(username)
                .password(password)
                .email(email)
                .name(name)
                .role(role)
                .build();
    }

    public Member updatedByOAuth2(OAuth2UserInfo oAuth2UserInfo){
        this.email = oAuth2UserInfo.getEmail();
        this.picture = oAuth2UserInfo.getImageUrl();
        this.name = oAuth2UserInfo.getName();

        return this;
    }

}
