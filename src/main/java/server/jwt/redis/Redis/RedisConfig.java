package server.jwt.redis.Redis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import server.jwt.redis.Redis.domain.DuplicateToken;
import server.jwt.redis.Redis.domain.IdToToken;
import server.jwt.redis.Redis.domain.LogoutToken;
import server.jwt.redis.Redis.domain.TokenToIpWithId;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableRedisRepositories
public class RedisConfig {

    @Value("${spring.redis.host}")
    private String host;

    @Value("${spring.redis.port}")
    private int port;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(host, port);
    }

    /**
     * key : refresh token
     * value : client ip, user id
     */
    @Bean(name = "tokenToIpWithIdRedisTemplate")
    public RedisTemplate<String, Object> tokenToIpWithIdRedisTemplate() {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();

        redisTemplate.setConnectionFactory(redisConnectionFactory());

        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(TokenToIpWithId.class));

        return redisTemplate;
    }


    /**
     * key : userId
     * value : refresh token
     */
    @Bean(name = "idToTokenRedisTemplate")
    public RedisTemplate<String, Object> idToTokenRedisTemplate() {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();

        redisTemplate.setConnectionFactory(redisConnectionFactory());

        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(IdToToken.class));

        return redisTemplate;
    }

    /**
     * key : oldRefreshToken
     * value :  String : "duplicateLogin"
     */
    @Bean(name = "duplicateTokenRedisTemplate")
    public RedisTemplate<String, String> duplicateTokenRedisTemplate() {
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();

        redisTemplate.setConnectionFactory(redisConnectionFactory());

        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new StringRedisSerializer());

        return redisTemplate;
    }


    /**
     * key : oldAccessToken
     * value :  String : "logout"
     */
    @Bean(name = "logoutTokenRedisTemplate")
    public RedisTemplate<String, Object> logoutTokenRedisTemplate() {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();

        redisTemplate.setConnectionFactory(redisConnectionFactory());

        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(LogoutToken.class));

        return redisTemplate;
    }



}
