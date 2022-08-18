package server.jwt.redis.domain.enums;

import lombok.Getter;

@Getter
public enum Role {
    ROLE_USER("ROLE_USER"),
    ROLE_ADMIN("ROLE_ADMIN");

    private String authority;

    Role(String authority) {
        this.authority = authority;
    }


}
