CREATE TABLE IF NOT EXISTS
	USERS (
		ID BIGINT AUTO_INCREMENT PRIMARY KEY,
		USERNAME VARCHAR(50) NOT NULL,
		PASSWORD VARCHAR(60) NOT NULL,
		ENABLED BOOLEAN NOT NULL,
        FIRST_NAME VARCHAR(50) NOT NULL,
        LAST_NAME VARCHAR(50) NOT NULL,
        EMAIL VARCHAR(50) NOT NULL,
        UNIQUE KEY USERNAME_UNIQUE (USERNAME),
        UNIQUE KEY EMAIL_UNIQUE (EMAIL)
	);

	CREATE TABLE IF NOT EXISTS AUTHORITIES (
         USER_ID BIGINT NOT NULL,
         ROLE VARCHAR(10) NOT NULL,
         FOREIGN KEY(USER_ID) REFERENCES USERS(ID),
         UNIQUE KEY USER_ROLE_UNIQUE (USER_ID, ROLE)
    );

    CREATE TABLE IF NOT EXISTS PASSWORD_RESET_TOKEN (
         ID BIGINT AUTO_INCREMENT PRIMARY KEY,
         SELECTOR VARCHAR(30) NOT NULL,
         VERIFIER VARCHAR(40) NOT NULL,
         EXPIRY_DATE TIMESTAMP NOT NULL,
         USER_ID BIGINT NOT NULL,
         FOREIGN KEY(USER_ID) REFERENCES USERS(ID)
    );