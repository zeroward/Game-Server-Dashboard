CREATE TABLE vpn_deliveries(device_id INTEGER PRIMARY KEY REFERENCES vpn_devices(id),encrypted_key BLOB,expires TEXT NOT NULL,created TEXT NOT NULL,consumed TEXT);
