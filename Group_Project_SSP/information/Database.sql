drop table logging;
drop table accounts;
drop table adminlevel;

CREATE DATABASE IF NOT EXISTS pythonlogin DEFAULT CHARACTER SET utf8 COLLATE
utf8_general_ci;
USE pythonlogin;
CREATE TABLE IF NOT EXISTS adminlevel(
    admin_level int(1) NOT NULL AUTO_INCREMENT,
    admin_level_desc varchar(255) NOT NULL,
PRIMARY KEY (admin_level)
);

INSERT INTO adminlevel (admin_level, admin_level_desc) VALUES (1, 'User');

INSERT INTO adminlevel (admin_level, admin_level_desc) VALUES (2, 'Admin Level 1');

INSERT INTO adminlevel (admin_level, admin_level_desc) VALUES (3, 'Admin Level 2');

INSERT INTO adminlevel (admin_level, admin_level_desc) VALUES (4, 'Admin Level 3');

INSERT INTO adminlevel (admin_level, admin_level_desc) VALUES (5, 'Admin Level 4');

INSERT INTO adminlevel (admin_level, admin_level_desc) VALUES (6, 'Admin Level 5');

CREATE TABLE IF NOT EXISTS accounts (
    id int(11) NOT NULL AUTO_INCREMENT,
    username varchar(50) NOT NULL,
    password varchar(255) NOT NULL,
    email varchar(255) NOT NULL,
    image_pathLocation varchar(1024) DEFAULT NULL,
    phone_number VARCHAR(20) NOT NULL,
    totp_secret VARCHAR(32) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_admin int(1) NOT NULL DEFAULT 1,
    symmetric_key varchar(255) NOT NULL,
    email_notifications BOOLEAN DEFAULT 0,
    password_create DATETIME DEFAULT NOW(),
    password_expiry_days INT DEFAULT NULL,
    password_expiry DATETIME DEFAULT NULL,
    PRIMARY KEY (id),
    CONSTRAINT FK_is_admin FOREIGN KEY (is_admin)
        REFERENCES adminlevel(admin_level)
);

INSERT INTO accounts (id, username, password, email, phone_number, totp_secret, is_admin, symmetric_key,password_expiry_days,password_expiry) VALUES (1, 'root', '$2b$12$1dKCvcI3XLIrE1D.Vsq.A.UtVW1.mLo2CnK2EBlr.sW.lLxExJ4Z6', 'gAAAAABmkjlIsXLFTfYwQLueqGkJXupH-gGw5-7jQqXv98uwCcTIJu86Wk0saC-McIFojyc1Lga2P7GLixGnRxa-ynr9Pwck31SDiUMR5_frjdlv9YkovNE=', '+6591722593', 'TMRDR5ZGZPBCBRDXKJTEBUJLWCX7V6L2', '6', 'MWRRU1BrTC1MTHY0OEgyNmlaVHdxdHhMWmhkVVRybnRFcTdSTUJRYXJHOD0=','9999999','9999-12-31 00:00:00');

CREATE DATABASE IF NOT EXISTS pythonlogin DEFAULT CHARACTER SET utf8 COLLATE
utf8_general_ci;
USE pythonlogin;
CREATE TABLE IF NOT EXISTS logging (
	id int(11) NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
	action VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    background_color varchar(10) NOT NULL,
PRIMARY KEY (id),
CONSTRAINT FK_user_id FOREIGN KEY (user_id)
    REFERENCES accounts(id)
);