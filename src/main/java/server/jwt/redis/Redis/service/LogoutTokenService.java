package server.jwt.redis.Redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import server.jwt.redis.Redis.domain.LogoutToken;
import server.jwt.redis.Redis.repository.LogoutTokenRepository;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class LogoutTokenService {

    private final LogoutTokenRepository logoutTokenRepository;


    public void saveLogoutToken(String accessToken, String logout, Duration ofMillis) {
        logoutTokenRepository.save(accessToken, logout, ofMillis);
    }

    public LogoutToken findLogoutToken(String logoutToken) {
        return logoutTokenRepository.findLogoutToken(logoutToken);
    }
}
