-- ferrosip schema (mysql); Kamailio table/column names.

-- expires/last_modified/time columns hold Unix seconds (ferrosip stores integers).


CREATE TABLE `subscriber` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL,
    `domain` VARCHAR(255) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `ha1` VARCHAR(255),
    `ha1b` VARCHAR(255),
    `rpid` VARCHAR(255)
);

CREATE TABLE `location` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL,
    `domain` VARCHAR(255),
    `contact` TEXT NOT NULL,
    `received` VARCHAR(255),
    `path` TEXT,
    `expires` BIGINT NOT NULL,
    `q` DOUBLE,
    `callid` VARCHAR(255) NOT NULL,
    `cseq` INTEGER NOT NULL,
    `cflags` INTEGER NOT NULL,
    `user_agent` VARCHAR(255) NOT NULL,
    `instance` VARCHAR(255),
    `reg_id` INTEGER,
    `last_modified` BIGINT NOT NULL
);

-- ims_usrloc_scscf (db_mode): one row per IMPU record, its contacts in
-- `contact` by `impu` (Kamailio's impu_contact join folded in).
CREATE TABLE `impu` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `impu` VARCHAR(255) NOT NULL,
    `impi` VARCHAR(255) NOT NULL,
    `reg_state` INTEGER NOT NULL,
    `ims_subscription_data` TEXT
);

CREATE TABLE `contact` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `impu` VARCHAR(255) NOT NULL,
    `contact` TEXT NOT NULL,
    `received` VARCHAR(255),
    `path` TEXT,
    `expires` BIGINT NOT NULL,
    `callid` VARCHAR(255),
    `cseq` INTEGER
);

-- ims_usrloc_scscf (db_mode): reg-event subscriptions, Kamailio's
-- subscriber_scscf; `presentity_uri` is the IMPU (Kamailio's impu_subscriber
-- join folded in), `expires` a Unix time, `sockinfo_str` where the NOTIFYs
-- go (the SUBSCRIBE's source).
CREATE TABLE `subscriber_scscf` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `watcher_uri` VARCHAR(255) NOT NULL,
    `watcher_contact` VARCHAR(255) NOT NULL,
    `presentity_uri` VARCHAR(255) NOT NULL,
    `event` INTEGER NOT NULL,
    `expires` BIGINT NOT NULL,
    `version` INTEGER NOT NULL,
    `local_cseq` INTEGER NOT NULL,
    `call_id` VARCHAR(255) NOT NULL,
    `from_tag` VARCHAR(255) NOT NULL,
    `to_tag` VARCHAR(255) NOT NULL,
    `record_route` TEXT,
    `sockinfo_str` VARCHAR(255)
);

CREATE TABLE `dialog` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `hash_entry` BIGINT NOT NULL,
    `hash_id` BIGINT NOT NULL,
    `callid` VARCHAR(255) NOT NULL,
    `from_uri` VARCHAR(255) NOT NULL,
    `from_tag` VARCHAR(255) NOT NULL,
    `to_uri` VARCHAR(255) NOT NULL,
    `to_tag` VARCHAR(255) NOT NULL,
    `caller_cseq` INTEGER NOT NULL,
    `callee_cseq` INTEGER NOT NULL,
    `caller_route_set` TEXT,
    `callee_route_set` TEXT,
    `caller_contact` VARCHAR(255) NOT NULL,
    `callee_contact` VARCHAR(255) NOT NULL,
    `caller_sock` VARCHAR(255) NOT NULL,
    `callee_sock` VARCHAR(255) NOT NULL,
    `state` INTEGER NOT NULL,
    `start_time` BIGINT NOT NULL,
    `timeout` BIGINT NOT NULL,
    `xdata` TEXT
);

CREATE TABLE `htable` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `key_name` VARCHAR(255) NOT NULL,
    `key_type` INTEGER NOT NULL,
    `value_type` INTEGER NOT NULL,
    `key_value` VARCHAR(255) NOT NULL,
    `expires` BIGINT NOT NULL
);

CREATE TABLE `dispatcher` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `setid` INTEGER NOT NULL,
    `destination` VARCHAR(255) NOT NULL,
    `flags` INTEGER NOT NULL,
    `priority` INTEGER NOT NULL,
    `attrs` VARCHAR(255),
    `description` VARCHAR(255)
);

CREATE TABLE `address` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `grp` INTEGER NOT NULL,
    `ip_addr` VARCHAR(255) NOT NULL,
    `mask` INTEGER NOT NULL,
    `port` INTEGER NOT NULL,
    `tag` VARCHAR(255)
);

CREATE TABLE `trusted` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `src_ip` VARCHAR(255) NOT NULL,
    `proto` VARCHAR(255) NOT NULL,
    `from_pattern` VARCHAR(255),
    `ruri_pattern` VARCHAR(255),
    `tag` VARCHAR(255),
    `priority` INTEGER NOT NULL
);

CREATE TABLE `domain` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `domain` VARCHAR(255) NOT NULL
);

CREATE TABLE `dbaliases` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `alias_username` VARCHAR(255) NOT NULL,
    `alias_domain` VARCHAR(255) NOT NULL,
    `username` VARCHAR(255) NOT NULL,
    `domain` VARCHAR(255) NOT NULL
);

CREATE TABLE `grp` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL,
    `domain` VARCHAR(255) NOT NULL,
    `grp` VARCHAR(255) NOT NULL
);

CREATE TABLE `dialplan` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `dpid` INTEGER NOT NULL,
    `pr` INTEGER NOT NULL,
    `match_op` INTEGER NOT NULL,
    `match_exp` VARCHAR(255) NOT NULL,
    `match_len` INTEGER NOT NULL,
    `subst_exp` VARCHAR(255),
    `repl_exp` VARCHAR(255),
    `attrs` VARCHAR(255)
);

CREATE TABLE `lcr_gw` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `lcr_id` INTEGER NOT NULL,
    `gw_name` VARCHAR(255) NOT NULL,
    `ip_addr` VARCHAR(255),
    `hostname` VARCHAR(255),
    `port` INTEGER,
    `params` VARCHAR(255),
    `uri_scheme` INTEGER,
    `transport` INTEGER,
    `strip` INTEGER,
    `prefix` VARCHAR(255),
    `tag` VARCHAR(255),
    `flags` INTEGER NOT NULL,
    `defunct` INTEGER
);

CREATE TABLE `lcr_rule` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `lcr_id` INTEGER NOT NULL,
    `prefix` VARCHAR(255),
    `from_uri` VARCHAR(255),
    `request_uri` VARCHAR(255),
    `mt_tvalue` VARCHAR(255),
    `stopper` INTEGER NOT NULL,
    `enabled` INTEGER NOT NULL
);

CREATE TABLE `lcr_rule_target` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `lcr_id` INTEGER NOT NULL,
    `rule_id` INTEGER NOT NULL,
    `gw_id` INTEGER NOT NULL,
    `priority` INTEGER NOT NULL,
    `weight` INTEGER NOT NULL
);

CREATE TABLE `acc` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `method` VARCHAR(255) NOT NULL,
    `from_tag` VARCHAR(255) NOT NULL,
    `to_tag` VARCHAR(255) NOT NULL,
    `callid` VARCHAR(255) NOT NULL,
    `sip_code` VARCHAR(255) NOT NULL,
    `sip_reason` VARCHAR(255) NOT NULL,
    `time` BIGINT NOT NULL,
    `src_user` VARCHAR(255),
    `dst_user` VARCHAR(255)
);

CREATE TABLE `missed_calls` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `method` VARCHAR(255) NOT NULL,
    `from_tag` VARCHAR(255) NOT NULL,
    `to_tag` VARCHAR(255) NOT NULL,
    `callid` VARCHAR(255) NOT NULL,
    `sip_code` VARCHAR(255) NOT NULL,
    `sip_reason` VARCHAR(255) NOT NULL,
    `time` BIGINT NOT NULL,
    `src_user` VARCHAR(255),
    `dst_user` VARCHAR(255)
);

CREATE TABLE `cdrs` (
    `cdr_id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `sip_call_id` VARCHAR(255) NOT NULL,
    `sip_from_tag` VARCHAR(255) NOT NULL,
    `sip_to_tag` VARCHAR(255) NOT NULL,
    `src_username` VARCHAR(255) NOT NULL,
    `src_domain` VARCHAR(255) NOT NULL,
    `dst_username` VARCHAR(255) NOT NULL,
    `dst_domain` VARCHAR(255) NOT NULL,
    `call_start_time` BIGINT NOT NULL,
    `duration` INTEGER NOT NULL
);

CREATE TABLE `uacreg` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `l_uuid` VARCHAR(255) NOT NULL,
    `l_username` VARCHAR(255) NOT NULL,
    `l_domain` VARCHAR(255) NOT NULL,
    `r_username` VARCHAR(255) NOT NULL,
    `r_domain` VARCHAR(255) NOT NULL,
    `realm` VARCHAR(255) NOT NULL,
    `auth_username` VARCHAR(255) NOT NULL,
    `auth_password` VARCHAR(255) NOT NULL,
    `auth_proxy` VARCHAR(255),
    `expires` INTEGER NOT NULL,
    `flags` INTEGER NOT NULL
);

CREATE TABLE `usr_preferences` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `uuid` VARCHAR(255) NOT NULL,
    `username` VARCHAR(255) NOT NULL,
    `domain` VARCHAR(255) NOT NULL,
    `attribute` VARCHAR(255) NOT NULL,
    `type` INTEGER NOT NULL,
    `value` VARCHAR(255) NOT NULL
);

CREATE TABLE `secfilter` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `action` INTEGER NOT NULL,
    `type` INTEGER NOT NULL,
    `data` VARCHAR(255) NOT NULL
);

CREATE TABLE `userblocklist` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL,
    `domain` VARCHAR(255) NOT NULL,
    `prefix` VARCHAR(255) NOT NULL,
    `allowlist` INTEGER NOT NULL
);

CREATE TABLE `globalblocklist` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `prefix` VARCHAR(255) NOT NULL,
    `allowlist` INTEGER NOT NULL,
    `description` VARCHAR(255)
);

CREATE TABLE `mtree` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `tprefix` VARCHAR(255) NOT NULL,
    `tvalue` VARCHAR(255) NOT NULL
);

CREATE TABLE `prefix_route` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `prefix` VARCHAR(255) NOT NULL,
    `route` VARCHAR(255) NOT NULL,
    `exclusive` INTEGER NOT NULL
);

CREATE INDEX location_aor ON `location` (`username`, `domain`);

CREATE INDEX subscriber_user ON `subscriber` (`username`, `domain`);

CREATE INDEX impu_impu ON `impu` (`impu`);

CREATE INDEX contact_impu ON `contact` (`impu`);

CREATE INDEX subscriber_scscf_dialog ON `subscriber_scscf` (`call_id`, `from_tag`);
