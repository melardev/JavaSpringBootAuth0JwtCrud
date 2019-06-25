package com.melardev.spring.websecjwt0.repositories;


import com.melardev.spring.websecjwt0.entities.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends CrudRepository<User, Long> {

    Optional<User> findByUsername(String username);

    // Optional<User> findByEmail(String email);

    //Same function of above but with HQL
    // @Query("select u from User u where u.email = ?1") Optional<User> findByEmailQuery(String email);
}
