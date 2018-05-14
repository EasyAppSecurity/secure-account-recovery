package net.easyappsecurity.account.recovery.repository.impl;

import net.easyappsecurity.account.recovery.domain.PasswordResetToken;
import net.easyappsecurity.account.recovery.repository.PasswordResetTokenRepository;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

@Repository
public class PasswordResetTokenRepositoryImpl implements PasswordResetTokenRepository {

    private Logger logger = Logger.getLogger(PasswordResetTokenRepositoryImpl.class);

    private class PasswordResetTokenMapper implements RowMapper<PasswordResetToken> {
        @Override
        public PasswordResetToken mapRow(ResultSet rs, int rowNum) throws SQLException {
            PasswordResetToken token = new PasswordResetToken();
            token.setId(rs.getLong("ID"));
            token.setSelector(rs.getString("SELECTOR"));
            token.setVerifier(rs.getString("VERIFIER"));
            token.setExpiryDate(rs.getDate("EXPIRY_DATE"));
            token.setUserId(rs.getLong("USER_ID"));
            return token;
        }
    }

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public PasswordResetToken save(PasswordResetToken token) {
        long tokenId = jdbcTemplate.update("INSERT INTO PASSWORD_RESET_TOKEN (ID, SELECTOR, VERIFIER, EXPIRY_DATE, USER_ID) VALUES(?, ?, ?, ?)",
                new Object[]{token.getId(),
                        token.getSelector(),
                        token.getVerifier(),
                        token.getExpiryDate(),
                        token.getId()}
        );
        token.setId(tokenId);
        return token;
    }

    @Override
    @Transactional(readOnly = true)
    public PasswordResetToken getToken(String selector) {
        try {
            return jdbcTemplate.queryForObject("SELECT * FROM PASSWORD_RESET_TOKEN WHERE SELECTOR=?",
                    new Object[]{selector},
                    new PasswordResetTokenMapper()
            );
        } catch (EmptyResultDataAccessException ex) {
            return null;
        }
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public PasswordResetToken update(PasswordResetToken token) {
        try {
            jdbcTemplate.update("UPDATE PASSWORD_RESET_TOKEN SET (SELECTOR, VERIFIER, EXPIRY_DATE) = (?,?,?) WHERE ID = ? ",
                    new Object[]{token.getSelector(), token.getVerifier(), token.getExpiryDate()}
            );
            return token;
        } catch (Exception ex) {
            logger.error("Couldn't update token", ex);
            return null;
        }
    }

    @Override
    @Transactional
    public void deleteExpiredSince(Date date) {
        jdbcTemplate.update("DELETE FROM PASSWORD_RESET_TOKEN WHERE EXPIRY_DATE <= ?",
                new Object[]{date});
    }

    @Override
    @Transactional
    public void delete(PasswordResetToken token) {
        jdbcTemplate.update("DELETE FROM PASSWORD_RESET_TOKEN WHERE ID = ?",
                new Object[]{token.getId()});
    }
}
