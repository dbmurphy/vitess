# Implementing IAM-like Authentication in Vitess with 8-Hour Time-based Salting

## Why This Implementation Works

Before diving into the technical details, it's important to understand why this approach is both feasible and robust in terms of password length support across the MySQL ecosystem:

### Maximum Password Length in MySQL:
* MySQL supports passwords up to 512 bytes in length. 
* This is a generous limit, allowing for complex, securely hashed, and encrypted passwords.

### Vitess vtgate Support:

Vitess’s vtgate is designed to be MySQL-compatible, which means it adheres to the same password length constraints as MySQL. Therefore, vtgate can handle passwords up to 512 bytes without issues.

#### Client Driver Compatibility:
**Python (mysql-connector-python)**: 

The Python MySQL client (mysql-connector-python) aligns with MySQL’s standards, supporting passwords up to 512 bytes.

**Java (MySQL Connector/J)**: 

Similarly, the Java MySQL client (MySQL Connector/J) supports the full range of MySQL-compatible passwords, up to 512 bytes.
Calculating the Size of the Encrypted Password

To confirm this implementation’s viability, consider the size of the encrypted password:

* Access Key and Secret Key
* * AWS access keys are 20 characters long, and secret keys are 40 characters long.

* Timestamp:
* * The timestamp used for salting (formatted as YYYYMMDDHH) is 10 characters long.

* Binary Data:
* * The combined binary data for encryption includes the timestamp, access key, secret key, and respective lengths, summing to approximately 73 bytes.

* AES-256 Encryption:
* * AES-256 encryption operates on 16-byte blocks. The 73-byte data is padded to 80 bytes before encryption, resulting in an 80-byte encrypted output.
* * Initialization Vector (IV):
* * * The AES-256 IV adds another 16 bytes.
* Total Size:
* * The total size of the password (IV + encrypted data) is 96 bytes, well within the 512-byte limit.

## Why Time-based Salting?
Time-based salting is an approach where a timestamp is included in the password generation process, creating a hash that is only valid for a specific time window. In this case, the salted hash is valid for 8 hours, matching the typical IAM session duration.

The idea is simple:

* Username: The IAM Role Name.
* Password: A salted and encrypted hash generated from the AWS Access Key, Secret Key, and a timestamp.

This mechanism ensures that the password is dynamic, reducing the risk of replay attacks while aligning with common security practices in cloud environments.
