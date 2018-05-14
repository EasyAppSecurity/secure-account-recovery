package net.easyappsecurity.account.recovery.domain;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;

public class PasswordResetToken implements Serializable {

    private static final int EXPIRATION = 60 * 24;

    private Long id;
    private String selector;
    private String verifier;
    private User user;
    private Long userId;
    private Date expiryDate;

    public PasswordResetToken() {
        super();
    }

    public PasswordResetToken(String selector, String verifier) {
        super();
        this.selector = selector;
        this.verifier = verifier;
        this.expiryDate = calculateExpiryDate(EXPIRATION);
    }

    public PasswordResetToken(String selector, String verifier, final User user) {
        super();
        this.selector = selector;
        this.verifier = verifier;
        this.user = user;
        this.userId = user.getId();
        this.expiryDate = calculateExpiryDate(EXPIRATION);
    }

    private Date calculateExpiryDate(final int expiryTimeInMinutes) {
        final Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(new Date().getTime());
        cal.add(Calendar.MINUTE, expiryTimeInMinutes);
        return new Date(cal.getTime().getTime());
    }

    public void updateToken(final String selector, final String verifier) {
        this.selector = selector;
        this.verifier = verifier;
        this.expiryDate = calculateExpiryDate(EXPIRATION);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }

    public String getSelector() {
        return selector;
    }

    public void setSelector(String selector) {
        this.selector = selector;
    }

    public String getVerifier() {
        return verifier;
    }

    public void setVerifier(String verifier) {
        this.verifier = verifier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PasswordResetToken that = (PasswordResetToken) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(selector, that.selector) &&
                Objects.equals(verifier, that.verifier) &&
                Objects.equals(user, that.user) &&
                Objects.equals(userId, that.userId) &&
                Objects.equals(expiryDate, that.expiryDate);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, selector, verifier, user, userId, expiryDate);
    }
}
