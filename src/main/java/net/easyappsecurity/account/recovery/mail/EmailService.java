package net.easyappsecurity.account.recovery.mail;

import net.easyappsecurity.account.recovery.domain.Email;

public interface EmailService {

    public void encryptAndSend(Email email, byte[] recipientCertificate) throws Exception;

    public void signAndSend(Email email) throws Exception;

    public void send(Email email);

}
