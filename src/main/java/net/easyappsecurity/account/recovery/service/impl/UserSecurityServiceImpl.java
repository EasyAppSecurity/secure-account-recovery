package net.easyappsecurity.account.recovery.service.impl;

import com.google.common.primitives.Bytes;
import net.easyappsecurity.account.recovery.domain.PasswordResetToken;
import net.easyappsecurity.account.recovery.domain.User;
import net.easyappsecurity.account.recovery.service.UserSecurityService;
import net.easyappsecurity.account.recovery.service.UserService;
import net.easyappsecurity.account.recovery.util.CryptoUtil;
import net.easyappsecurity.account.recovery.validation.Authorities;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Calendar;

@Service
public class UserSecurityServiceImpl implements UserSecurityService {

    private static final int SELECTOR_LEN = 15;
    private static final int VERIFIER_LEN = 18;

    @Autowired
    private UserService userService;

    @Override
    public String createPasswordResetToken(User user) {
        final String selector = RandomStringUtils.randomAlphanumeric(SELECTOR_LEN);
        final String verifier = RandomStringUtils.randomAlphabetic(VERIFIER_LEN);

        userService.createPasswordResetTokenForUser(user,
                selector,
                new String(CryptoUtil.sha256(verifier.getBytes()))
        );

        return new String(Base64.encode(Bytes.concat(selector.getBytes(), verifier.getBytes())));
    }

    @Override
    public String validatePasswordResetToken(long id, String token) {
        final String decodedToken = new String(Base64.decode(token));
        final String selector = decodedToken.substring(0, SELECTOR_LEN - 1);

        final PasswordResetToken passToken = userService.findPasswordResetToken(selector, true);
        if ((passToken == null) || (passToken.getUser().getId() != id)) {
            return "invalidToken";
        }

        final String verifier = decodedToken.substring(SELECTOR_LEN, SELECTOR_LEN + VERIFIER_LEN - 1);
        // time-constant comparison
        if (!MessageDigest.isEqual(passToken.getVerifier().getBytes(), CryptoUtil.sha256(verifier.getBytes()))) {
            userService.deletePasswordResetToken(passToken);
            return "invalidToken";
        }


        final Calendar cal = Calendar.getInstance();
        if ((passToken.getExpiryDate().getTime() - cal.getTime().getTime()) <= 0) {
            return "invalidToken";
        }

        final User user = passToken.getUser();
        final Authentication auth = new UsernamePasswordAuthenticationToken(
                user, null, Arrays.asList(
                new SimpleGrantedAuthority(Authorities.CHANGE_PASSWORD)
        ));
        SecurityContextHolder.getContext().setAuthentication(auth);
        return null;
    }


}
