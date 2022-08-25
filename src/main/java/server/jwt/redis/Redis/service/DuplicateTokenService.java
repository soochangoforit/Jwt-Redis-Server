package server.jwt.redis.Redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import server.jwt.redis.Redis.domain.DuplicateToken;
import server.jwt.redis.Redis.repository.DuplicateTokenRepository;

@Service
@RequiredArgsConstructor
public class DuplicateTokenService {

    private final DuplicateTokenRepository duplicateTokenRepository;


    public void saveOldTokenForDuplicate(String oldToken) {
        duplicateTokenRepository.save(oldToken, "duplicate login");
    }

    public String findOldTokenFromDuplicate(String oldRefreshToken) {
        return duplicateTokenRepository.findStateByOldToken(oldRefreshToken);
    }
}
