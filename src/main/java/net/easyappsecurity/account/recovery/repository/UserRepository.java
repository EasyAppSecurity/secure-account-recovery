package net.easyappsecurity.account.recovery.repository;

import net.easyappsecurity.account.recovery.domain.User;

public interface UserRepository {

    public User save(User user);

    public User findByUsername(String username);

    public User findByEmail(String email);

    public User findById(Long id);

    public User update(User user);

    public User changePassword(User user);

}
