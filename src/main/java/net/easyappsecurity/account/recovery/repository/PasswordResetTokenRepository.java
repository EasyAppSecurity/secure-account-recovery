package net.easyappsecurity.account.recovery.repository;

import net.easyappsecurity.account.recovery.domain.PasswordResetToken;

import java.util.Date;

public interface PasswordResetTokenRepository {

    public PasswordResetToken save(PasswordResetToken token);

    public PasswordResetToken update(PasswordResetToken token);

    public PasswordResetToken getToken(String selector);

    public void deleteExpiredSince(Date date);

    public void delete(PasswordResetToken token);

}
