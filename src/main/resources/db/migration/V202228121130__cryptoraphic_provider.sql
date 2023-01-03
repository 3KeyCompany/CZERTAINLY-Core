CREATE TABLE token_instance_reference (
	uuid UUID NOT NULL,
	i_author VARCHAR NOT NULL,
	i_cre TIMESTAMP NOT NULL,
	i_upd TIMESTAMP NOT NULL,
	name VARCHAR NOT NULL,
	token_instance_uuid VARCHAR NOT NULL,
	description VARCHAR NULL DEFAULT NULL,
	status VARCHAR NOT NULL,
	kind VARCHAR NOT NULL,
	connector_uuid UUID NULL DEFAULT NULL,
	connector_name VARCHAR NULL DEFAULT NULL,
	attributes TEXT NULL DEFAULT NULL,
	PRIMARY KEY (uuid)
);

CREATE TABLE token_profile (
	uuid UUID NOT NULL,
	i_author VARCHAR NOT NULL,
	i_cre TIMESTAMP NOT NULL,
	i_upd TIMESTAMP NOT NULL,
	name VARCHAR NOT NULL,
	description VARCHAR NULL DEFAULT NULL,
	token_instance_name VARCHAR NULL DEFAULT NULL,
	token_instance_ref_uuid UUID NOT NULL,
	attributes TEXT NULL DEFAULT NULL,
	enabled BOOLEAN NULL DEFAULT NULL,
	PRIMARY KEY (uuid)
);

CREATE TABLE cryptographic_key (
	uuid UUID NOT NULL,
	i_author VARCHAR NOT NULL,
	i_cre TIMESTAMP NOT NULL,
	i_upd TIMESTAMP NOT NULL,
	name VARCHAR NOT NULL,
	token_profile_uuid UUID NULL,
	description VARCHAR NULL DEFAULT NULL,
	PRIMARY KEY (uuid)
);

CREATE TABLE cryptographic_key_content (
	uuid UUID NOT NULL,
	type VARCHAR NOT NULL,
	key_reference_uuid UUID NOT NULL,
	cryptographicAlgorithm VARCHAR NULL DEFAULT NULL,
	format VARCHAR NULL,
	keyData VARCHAR NOT NULL,
	length INTEGER NULL,
	PRIMARY KEY (uuid)
);

alter table if exists token_instance_reference
    add constraint token_instance_reference_to_connector_key
    foreign key (connector_uuid)
    references connector;

alter table if exists token_profile
    add constraint token_profile_to_token_instance_key
    foreign key (token_instance_ref_uuid)
    references token_instance_reference;

alter table if exists cryptographic_key
    add constraint cryptographic_key_to_token_profile_key
    foreign key (token_profile_uuid)
    references token_profile;

alter table if exists cryptographic_key_content
    add constraint cryptographic_key_to_key_content_key
    foreign key (key_reference_uuid)
    references cryptographic_key;


--TODO Add End points and function groups into the database for the Cryptographic Provider