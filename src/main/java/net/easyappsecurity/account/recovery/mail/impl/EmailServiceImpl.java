package net.easyappsecurity.account.recovery.mail.impl;

import net.easyappsecurity.account.recovery.domain.Email;
import net.easyappsecurity.account.recovery.mail.EmailService;
import net.easyappsecurity.account.recovery.mail.MailEncryptionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

@Service
public class EmailServiceImpl implements EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailServiceImpl.class);

    @Autowired
    private JavaMailSender mailSender;

    public void encryptAndSend(Email mail, byte[] repipientCertificate) throws Exception {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        helper.setTo(mail.getTo().toArray(new String[mail.getTo().size()]));
        helper.setReplyTo(mail.getFrom());
        helper.setFrom(mail.getFrom());
        helper.setSubject(mail.getSubject());
        helper.setText(mail.getMessage(), true);

        mailSender.send(MailEncryptionUtil.encryptMessage(message, repipientCertificate));

    }

    public void signAndSend(Email mail) throws Exception {

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        helper.setTo(mail.getTo().toArray(new String[mail.getTo().size()]));
        helper.setReplyTo(mail.getFrom());
        helper.setFrom(mail.getFrom());
        helper.setSubject(mail.getSubject());
        helper.setText(mail.getMessage(), true);

        mailSender.send(MailEncryptionUtil.signMessage(message));

    }

    public void send(Email mail) {

        if (mail.isHtml()) {
            try {
                sendHtmlMail(mail);
            } catch (MessagingException e) {
                logger.error("Could not send email to : {} Error = {}", mail.toString(), e.getMessage());
            }
        } else {
            sendPlainTextMail(mail);
        }

    }

    private void sendHtmlMail(Email mail) throws MessagingException {

        boolean isHtml = true;

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        helper.setTo(mail.getTo().toArray(new String[mail.getTo().size()]));
        helper.setReplyTo(mail.getFrom());
        helper.setFrom(mail.getFrom());
        helper.setSubject(mail.getSubject());
        helper.setText(mail.getMessage(), isHtml);

        if (mail.getCc().size() > 0) {
            helper.setCc(mail.getCc().toArray(new String[mail.getCc().size()]));
        }

        mailSender.send(message);
    }

    private void sendPlainTextMail(Email mail) {
        SimpleMailMessage mailMessage = new SimpleMailMessage();

        mail.getTo().toArray(new String[mail.getTo().size()]);
        mailMessage.setTo(mail.getTo().toArray(new String[mail.getTo().size()]));
        mailMessage.setReplyTo(mail.getFrom());
        mailMessage.setFrom(mail.getFrom());
        mailMessage.setSubject(mail.getSubject());
        mailMessage.setText(mail.getMessage());

        if (mail.getCc().size() > 0) {
            mailMessage.setCc(mail.getCc().toArray(new String[mail.getCc().size()]));
        }

        mailSender.send(mailMessage);

    }

}
