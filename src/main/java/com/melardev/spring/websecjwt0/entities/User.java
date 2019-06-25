package com.melardev.spring.websecjwt0.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
public class User extends TimestampedEntity implements UserDetails {


    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE})
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
    private Set<Role> roles;

    @Column(nullable = false, length = 20, unique = true)
    @NotBlank(message = "Username can't be empty")
    private String username;
    /*
        @Column(nullable = false, unique = true)
        @Email(message = "Invalid email")
        @NotBlank(message = "Email can't be empty")
        private String email;
    */

    // Make it only available to read
    // Or @JsonProperty(access = Access.WRITE_ONLY)
    @Column(nullable = false)
    @NotBlank(message = "Password can't be empty")
    private String password;

    public User() {
    }

    public User(String username, String password) {
        this.username = username;
        this.password = password;

    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        if (roles != null) {
            roles.forEach(role -> {
                if (role.getName() != null) {
                    authorities.add(new SimpleGrantedAuthority(role.getName()));
                }
            });
        }
        return authorities;
    }

    @Override
    @JsonIgnore // Ignore password in JSON responses
    public String getPassword() {
        return password;
    }

    @JsonProperty
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }


}
