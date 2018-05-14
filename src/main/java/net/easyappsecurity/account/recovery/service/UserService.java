package net.easyappsecurity.account.recovery.service;

import net.easyappsecurity.account.recovery.domain.PasswordResetToken;
import net.easyappsecurity.account.recovery.domain.User;

import java.util.Date;

public interface UserService {

    public User findByEmail(String email);

    public void createPasswordResetTokenForUser(final User user, final String selector, String verifier);

    public PasswordResetToken findPasswordResetToken(String selector, boolean userInclude);

    public void changeUserPassword(User user);

    public void deleteExpiredTokens(Date date);

    public void deletePasswordResetToken(PasswordResetToken token);

}
