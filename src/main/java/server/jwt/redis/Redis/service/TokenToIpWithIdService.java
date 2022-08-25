package server.jwt.redis.Redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import server.jwt.redis.Redis.domain.TokenToIpWithId;
import server.jwt.redis.Redis.repository.TokenToIpWithIdRepository;

@Service
@RequiredArgsConstructor
public class TokenToIpWithIdService {

    private final TokenToIpWithIdRepository tokenToIpWithIdRepository;

    public void saveTokenWithClientIpAndId(String refreshToken, String clientIp, Long userId) {
        TokenToIpWithId tokenToIpWithId = new TokenToIpWithId(clientIp, userId.toString());
        tokenToIpWithIdRepository.save(refreshToken, tokenToIpWithId);
    }

    public void deleteToken(String oldToken) {
        tokenToIpWithIdRepository.delete(oldToken);
    }

    public TokenToIpWithId findValueByToken(String oldRefreshToken) {
        return tokenToIpWithIdRepository.findValueByToken(oldRefreshToken);
    }

    public void deleteValueByToken(String oldRefreshToken) {
        tokenToIpWithIdRepository.delete(oldRefreshToken);
    }
}
