package net.easyappsecurity.account.recovery.service;

import net.easyappsecurity.account.recovery.domain.User;

public interface UserSecurityService {

    public String createPasswordResetToken(User user);

    public String validatePasswordResetToken(long id, String selector);

}
