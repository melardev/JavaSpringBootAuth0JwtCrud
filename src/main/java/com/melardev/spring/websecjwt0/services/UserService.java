package com.melardev.spring.websecjwt0.services;


import com.melardev.spring.websecjwt0.entities.Role;
import com.melardev.spring.websecjwt0.entities.User;
import com.melardev.spring.websecjwt0.repositories.RoleRepository;
import com.melardev.spring.websecjwt0.repositories.UsersRepository;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepository roleRepository;
    private final UsersRepository userRepository;

    @Autowired // Not needed (since Spring 4.3?)
    public UserService(UsersRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        if (!user.isPresent()) {
            throw new UsernameNotFoundException("Invalid username or password.");
        }
        // User exists, we have to return an Implementation of UserDetails, let's use the default
        return user.get();
    }

    public User createUser(String username, String password) {
        return createUser(new User(username, password));
    }

    public User createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRoles() == null || user.getRoles().size() == 0) {
            Optional<Role> optionUserRole = roleRepository.findByNameHql("ROLE_USER");
            Role userRole = optionUserRole.orElseGet(() -> roleRepository.save(new Role("ROLE_USER")));
            assert userRole.getId() != null;
            user.setRoles(Collections.singleton(userRole));
        } else {
            Set<Role> roles = user.getRoles();
            Set<Role> persistedRoles = new HashSet<>(roles.size());
            for (Role role : roles) {
                if (role.getId() == null) {
                    Role savedRole = roleRepository.save(role);
                    assert savedRole.getId() != null;
                    persistedRoles.add(savedRole);
                } else {
                    persistedRoles.add(role);
                }
            }

            user.setRoles(persistedRoles);
        }

        return userRepository.save(user);

    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public long count() {
        return userRepository.count();
    }
}