package server.jwt.redis.Redis;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.SecondaryTable;
import java.io.Serializable;

@Getter
@Setter
public class RedisValue implements Serializable {

    private String clientIp;
    private String userId;

    public RedisValue(String clientIp, String userId) {
        super();
        this.clientIp = clientIp;
        this.userId = userId;
    }

    public RedisValue() {}


}
