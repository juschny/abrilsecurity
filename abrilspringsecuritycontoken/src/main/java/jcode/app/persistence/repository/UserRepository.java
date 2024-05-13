package jcode.app.persistence.repository;

import jcode.app.persistence.entity.UserEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity , Long> {

    Optional<UserEntity> findUserEntityByUsername(String username);
    //@Query("SELECT u FROM UserEntity u WHERE u.username = ?")
    //Optional<UserEntity> findUser(String username);

}
