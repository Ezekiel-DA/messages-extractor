# Super basic SMS extractor for iPhone backups

Quick start:
* clone this repo
* `npm install`
* `node extractor.js <your iPhone backup password> '<phone number of contact>'`

Note: the phone number will most likely need to be in the format: `+<country code><10 digit phone number>`

Right now this will dump all attachments from the given conversation to the CWD. You probably want to run this somewhere other than the root of the repo.

All credit for understanding the actual decryption process should go to `andrewdotn` from [this SO question](https://stackoverflow.com/questions/1498342/how-to-decrypt-an-encrypted-apple-itunes-iphone-backup).