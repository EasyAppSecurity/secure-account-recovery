package net.easyappsecurity.account.recovery.controller;

import net.easyappsecurity.account.recovery.domain.Email;
import net.easyappsecurity.account.recovery.domain.User;
import net.easyappsecurity.account.recovery.mail.EmailService;
import net.easyappsecurity.account.recovery.service.UserSecurityService;
import net.easyappsecurity.account.recovery.service.UserService;
import net.easyappsecurity.account.recovery.util.RequestHelper;
import net.easyappsecurity.account.recovery.validation.ErrorType;
import net.easyappsecurity.account.recovery.validation.RestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;
import java.util.Locale;

@RestController
@RequestMapping("user")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private UserSecurityService userSecurityService;

    @Autowired
    private MessageSource messages;

    @Autowired
    private EmailService emailService;

    @RequestMapping(value = "resetPassword", method = RequestMethod.POST)
    public ResponseEntity<?> resetPassword(HttpServletRequest request, @RequestParam("email") String email,
                                           @RequestParam("recipientCertificate") byte[] recipientCertificate) {
        Locale locale = request.getLocale();

        User user = userService.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        String token = userSecurityService.createPasswordResetToken(user);

        Email mail = new Email();
        mail.setFrom(messages.getMessage("support.email", null, locale));
        mail.setSubject(messages.getMessage("message.resetPassword", null, locale));
        mail.setTo(Collections.singletonList(user.getEmail()));
        mail.setMessage(RequestHelper.getAppUrl(request) + "/user/changePassword?id=" + user.getId() + "&token=" + token);

        try {
            emailService.encryptAndSend(mail, recipientCertificate);
        } catch (Exception ex) {
            logger.error("Error while sending email", ex);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(HttpStatus.OK);
    }


    @RequestMapping(value = "/changePassword", method = RequestMethod.POST)
    public ResponseEntity<?> changePassword(Locale locale, @RequestParam("id") long id, @RequestParam("token") String token) {
        String result = userSecurityService.validatePasswordResetToken(id, token);
        if (result != null) {
            throw new RestException("token", ErrorType.INVALID_TOKEN,
                    messages.getMessage("auth.message." + result, null, locale));
        }

        return new ResponseEntity<>(HttpStatus.OK);
    }

}
