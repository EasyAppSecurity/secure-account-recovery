package net.easyappsecurity.account.recovery.service.impl;

import net.easyappsecurity.account.recovery.domain.PasswordResetToken;
import net.easyappsecurity.account.recovery.domain.User;
import net.easyappsecurity.account.recovery.repository.PasswordResetTokenRepository;
import net.easyappsecurity.account.recovery.repository.UserRepository;
import net.easyappsecurity.account.recovery.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    @Transactional
    public void createPasswordResetTokenForUser(final User user, final String selector, String verifier) {
        final PasswordResetToken resetToken = new PasswordResetToken(selector, verifier, user);
        passwordResetTokenRepository.save(resetToken);
    }

    @Override
    public PasswordResetToken findPasswordResetToken(String selector, boolean userInclude) {
        PasswordResetToken resetToken = passwordResetTokenRepository.getToken(selector);

        if (resetToken != null && userInclude) {
            resetToken.setUser(
                    userRepository.findById(resetToken.getUserId()));
        }

        return passwordResetTokenRepository.getToken(selector);
    }

    @Override
    public void changeUserPassword(User user) {
        userRepository.changePassword(user);
    }

    @Override
    public void deleteExpiredTokens(Date date) {
        passwordResetTokenRepository.deleteExpiredSince(date);
    }

    @Override
    public void deletePasswordResetToken(PasswordResetToken token) {
        passwordResetTokenRepository.delete(token);
    }
}
