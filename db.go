package main

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	db *sql.DB
}

func (db DB) AddDomain(ip, domain string) error {
	_, err := db.db.Exec("INSERT OR IGNORE INTO `domain` (`ip`,`domain`) VALUES (?, ?);", ip, domain)
	return err
}

func (db DB) SetDomainRST(ip string) error {
	_, err := db.db.Exec("UPDATE `domain` SET `rst` = TRUE WHERE `ip` = ?;", ip)
	return err
}

func OpenDB(name string) (*DB, error) {
	db, err := sql.Open("sqlite3", name)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `domain` (`ip` VARCHAR(128) NOT NULL, `domain` VARCHAR(128) NOT NULL, `rst` BOOL DEFAULT FALSE);")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS `domain_ip` ON `domain` (`ip`, `domain`);")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS `ip` ON `domain` (`ip`);")
	if err != nil {
		return nil, err
	}
	return &DB{
		db,
	}, nil
}
