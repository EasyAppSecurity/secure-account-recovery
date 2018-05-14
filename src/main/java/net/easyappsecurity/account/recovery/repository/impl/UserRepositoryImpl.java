package net.easyappsecurity.account.recovery.repository.impl;

import net.easyappsecurity.account.recovery.domain.User;
import net.easyappsecurity.account.recovery.repository.UserRepository;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;

@Repository
public class UserRepositoryImpl implements UserRepository {

    private Logger logger = Logger.getLogger(UserRepositoryImpl.class);

    private class UserRowMapper implements RowMapper<User> {
        @Override
        public User mapRow(ResultSet rs, int rowNum) throws SQLException {
            User user = new User();
            user.setId(rs.getLong("ID"));
            user.setUsername(rs.getString("USERNAME"));
            user.setPassword(rs.getString("PASSWORD"));
            user.setEnabled(rs.getBoolean("ENABLED"));
            user.setRole(rs.getString("ROLE"));
            user.setFirstname(rs.getString("FIRST_NAME"));
            user.setLastname(rs.getString("LAST_NAME"));
            user.setEmail(rs.getString("EMAIL"));
            return user;
        }
    }

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public User save(User user) {
        long userId = jdbcTemplate.update("INSERT INTO USERS (ID, USERNAME, PASSWORD, ENABLED, FIRST_NAME, LAST_NAME, EMAIL) VALUES(?, ?, ?, ?, ?, ?, ?)",
                new Object[]{user.getId(), user.getUsername(), user.getPassword(), user.isEnabled(), user.getFirstname(), user.getLastname(), user.getEmail()});
        user.setId(userId);
        //TODO the update doesnt see the previous update
        jdbcTemplate.update("INSERT INTO AUTHORITIES (USER_ID, ROLE) VALUES(?, ?)",
                new Object[]{user.getId(), user.getRole()});
        return user;
    }

    @Override
    public User findByUsername(String username) {
        try {
            return jdbcTemplate.queryForObject("SELECT usr.ID, usr.USERNAME, usr.PASSWORD, usr.ENABLED, auth.ROLE, usr.FIRST_NAME, usr.LAST_NAME, usr.EMAIL " +
                            "FROM USERS usr INNER JOIN AUTHORITIES auth ON usr.ID = auth.USER_ID " +
                            "WHERE usr.USERNAME=?",
                    new Object[]{username},
                    new UserRowMapper()
            );
        } catch (Exception ex) {
            logger.error("Couldn't find user", ex);
            return null;
        }
    }

    @Override
    public User findByEmail(String email) {
        try {
            return jdbcTemplate.queryForObject("SELECT usr.ID, usr.USERNAME, usr.PASSWORD, usr.ENABLED, auth.ROLE, usr.FIRST_NAME, usr.LAST_NAME, usr.EMAIL " +
                            "FROM USERS usr INNER JOIN AUTHORITIES auth ON usr.ID = auth.USER_ID " +
                            "WHERE usr.EMAIL=?",
                    new Object[]{email},
                    new UserRowMapper()
            );
        } catch (EmptyResultDataAccessException emptyEx) {
            return null;
        } catch (Exception ex) {
            logger.error("Couldn't find user by email", ex);
            return null;
        }
    }

    @Override
    public User findById(Long id) {
        try {
            return jdbcTemplate.queryForObject("SELECT usr.ID, usr.USERNAME, usr.PASSWORD, usr.ENABLED, auth.ROLE, usr.FIRST_NAME, usr.LAST_NAME, usr.EMAIL " +
                            "FROM USERS usr INNER JOIN AUTHORITIES auth ON usr.ID = auth.USER_ID " +
                            "WHERE usr.ID=?",
                    new Object[]{id},
                    new UserRowMapper()
            );
        } catch (Exception ex) {
            logger.error("Couldn't find user", ex);
            return null;
        }
    }

    @Override
    public User update(User user) {
        try {
            long userId = jdbcTemplate.update("UPDATE USERS SET (FIRST_NAME, LAST_NAME, ENABLED) = (?, ?, ?) WHERE ID = ? ",
                    new Object[]{user.getFirstname(), user.getLastname(), user.isEnabled(), user.getId()}
            );
            user.setId(userId);
            return user;
        } catch (Exception ex) {
            logger.error("Couldn't update user", ex);
            return null;
        }
    }

    @Override
    public User changePassword(User user) {
        try {
            long userId = jdbcTemplate.update("UPDATE USERS SET (PASSWORD) = (?) WHERE ID = ? ",
                    new Object[]{user.getPassword(), user.getId()}
            );
            user.setId(userId);
            return user;
        } catch (Exception ex) {
            logger.error("Couldn't update password", ex);
            return null;
        }
    }
}
