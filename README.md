# Super basic SMS extractor for iPhone backups

Quick start:
* clone this repo
* `npm i`
* `node extractor.js <your iPhone backup password> 'Library/SMS/sms.db'`

This should technically work with any file in the backup instead of `sms.db` for now.

All credit for understanding the actual decryption process should go to `andrewdotn` from [this SO question](https://stackoverflow.com/questions/1498342/how-to-decrypt-an-encrypted-apple-itunes-iphone-backup).