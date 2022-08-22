package server.jwt.redis.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import server.jwt.redis.domain.Member;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByNickname(String nickname);

    boolean existsByUsernameAndEmailAndNickname(String username, String email, String nickname);

    Optional<Member> findByEmail(String email);

    Optional<Member> findByUsername(String username);

    @Query(value = "select m.username from Member m where m.id = :id")
    String findUsernameById(@Param("id") long id);
}
