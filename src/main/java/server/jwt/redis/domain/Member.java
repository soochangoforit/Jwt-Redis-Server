package server.jwt.redis.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import server.jwt.redis.domain.enums.Role;

import javax.persistence.*;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String nickname;

    @Column
    private String picture;

    @Enumerated(EnumType.STRING)
    private Role role;


    @Builder
    private Member(String username, String password, String email , String nickname, String picture ,Role role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.nickname = nickname;
        this.picture = picture;
        this.role = role;
    }

    public static Member of(String username, String password, String email, String nickname, Role role) {
        return Member.builder()
                .username(username)
                .password(password)
                .email(email)
                .nickname(nickname)
                .role(role)
                .build();
    }

}
