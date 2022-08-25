package server.jwt.redis.Redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import server.jwt.redis.Redis.domain.IdToToken;
import server.jwt.redis.Redis.repository.IdToTokenRepository;

import java.time.Duration;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class IdToTokenService {

    private final IdToTokenRepository idToTokenRepository;

    public void deleteByUserId(String userId) {
        idToTokenRepository.delete(userId);
    }

    public String findTokenById(Long userId) {

        String oldToken = idToTokenRepository.findTokenById(userId.toString());

        return oldToken;
    }

    public void saveUserIdWithRefreshToken(Long userId, String refreshToken) {
        IdToToken idToToken = new IdToToken(refreshToken);
        idToTokenRepository.save(userId, idToToken);
    }
}
