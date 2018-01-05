const crypto = require('crypto')
const webcrypto = require('@trust/webcrypto')
const fs = require('fs')
const process = require('process')
const path = require('path')
const { promisify } = require('util')
const bplist = require('bplist-parser')
const sqlite = require('sqlite')
const uuidv4 = require('uuid/v4')
const PDFDocument = require('pdfkit')

const backupPath = path.join(process.env.APPDATA, 'Apple Computer/MobileSync/Backup')
const smsDatabaseFilename = 'Library/SMS/sms.db'

const protectionClasses = ['Unused',
'NSFileProtectionComplete', 'NSFileProtectionCompleteUnlessOpen', 'NSFileProtectionCompleteUntilFirstUserAuthentication',
'NSFileProtectionNone', 'NSFileProtectionRecovery?', 'kSecAttrAccessibleWhenUnlocked', 'kSecAttrAccessibleAfterFirstUnlock',
'kSecAttrAccessibleAlways', 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly', 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
'kSecAttrAccessibleAlwaysThisDeviceOnly']

// these key types describe class keys, not the generic keybag itself, and should be bundled together by Protection Class
const classKeyTypes = ['CLAS', 'WRAP', 'WPKY', 'KTYP', 'PBKY', 'UUID']

// promisify some commonly used native APIs
const [pbkdf2, readdir, unlink, parseplistFile] = [crypto.pbkdf2, fs.readdir, fs.unlink, bplist.parseFile].map(promisify)

async function readManifestPlist (backupDir) {
  return parseplistFile(path.join(backupPath, backupDir, 'Manifest.plist'))
}

/**
 * Writes a file with the contents of a given stream, returning a Promise once the write has completed.
 * If necessary (i.e. when writing out temp files) file paths are made unique by prepending a UUID to the filename.
 * @param {String} filename
 * @param {Stream} contentStream
 * @param {Boolean} tempFile - if true, make the filename unique and write out to the temp directory; otherwise, write out to CWD with the original filename
 * @returns {String} the path of the written file (absolute if temp, relative if not. Yes, this sucks)
 */
async function writeOutFileStream (filename, contentStream, tempFile) {
  if (tempFile) {
    filename = path.join(process.env.TMPDIR || process.env.TMP || process.env.TEMP, uuidv4() + '-' + filename)
  }
  return new Promise(resolve => { contentStream.pipe(fs.createWriteStream(filename).on('finish', () => resolve(filename))) })
}

/**
 * Extract the manifest key from Manifest.plist and return it's class and wrapped key (to be unwrapped)
 * @param {String} backupDir
 */
async function readManifestKey (backupDir) {
  let manifest = (await readManifestPlist(backupDir))[0].ManifestKey
  let keyClass = manifest.readInt32LE()
  let wrappedKey = manifest.slice(4)
  return {keyClass, wrappedKey}
}

/**
 * Import a Key Wrapping key (in the RFC3394 sense)
 * @param {String} key - the raw unwrapping key
 */
async function importKWKey (key) {
  return webcrypto.subtle.importKey('raw', key, {name: 'AES-KW'}, false, ['wrapKey', 'unwrapKey'])
}

/**
 * Unwrap a wrapped key (in the RFC3394 sense)
 * @param {*} wrappedKey - the key to unwrap
 * @param {*} unwrappingKey - the unwrapping key (created through importKWKey from the raw key)
 */
async function unwrapKey (wrappedKey, unwrappingKey) {
  return webcrypto.subtle.unwrapKey('raw', wrappedKey, unwrappingKey, {name: 'AES-KW'}, {name: 'AES-CBC', length: 256}, false, ['unwrapKey'])
  .then(unwrappedKey => unwrappedKey.handle)
}

async function readKeybag (backupDir) {
  let manifest = await readManifestPlist(backupDir)
  let keybag = manifest[0]['BackupKeyBag']

  let bagData = {}
  bagData.classes = {}
  let tempClassKey = {}

  let i = 0
  while (i < keybag.length) {
    let type = keybag.slice(0 + i, 4 + i).toString('ascii')
    let length = keybag.readInt32BE(4 + i)
    let data = length === 4 ? keybag.readInt32BE(8 + i) : keybag.slice(8 + i, 8 + i + length)
    i += 8 + length

    if (type === 'UUID' && bagData.UUID) { // already have the bag UUID; this is the start of a class key
      tempClassKey = {}
      tempClassKey[type] = data
    }
    else if (type === 'CLAS') {
      bagData.classes[protectionClasses[data]] = tempClassKey
    }
    else if (classKeyTypes.includes(type) && bagData.UUID && bagData.hasOwnProperty('WRAP')) {
      tempClassKey[type] = data
    }
    else {
      bagData[type] = data
    }
  }
  return bagData
}

async function constructPasskey (password, keybag) {
  let intermediatePasscode = await pbkdf2(password, keybag.DPSL, keybag.DPIC, 32, 'sha256')
  return pbkdf2(intermediatePasscode, keybag.SALT, keybag.ITER, 32, 'sha1')
}

/**
 * Decrypt some data through AES256 in CBC mode. Assumes 0 IV.
 * @param {Buffer} unwrappedKey - the unwrapped key to use
 * @param {Stream} dataStream - a readable Stream of the data to decrypt
 * @returns {Crypto.Decipher} a readable Stream of the decrypted data
 */
function decryptAESCBC (unwrappedKey, dataStream) {
  let dbDecrypter = crypto.createDecipheriv('aes-256-cbc', unwrappedKey, new Buffer(16))
  return dataStream.pipe(dbDecrypter)
}

/**
 * Decrypt a file from the backup.
 * @param {String} backupDir - the root of the given backup
 * @param {String} filename - the name of the file in the iOS filesystem
 * @param {Object} keybag  - the keybag to use
 * @param {Database} manifestDb - the SQLite3 DB opened from a decrypted manifest.db file
 * @returns {Crypto.Decipher} a Stream that can be read to get the decrypted contents of the requested file
 */
async function decryptFile (backupDir, filename, keybag, manifestDb) {
  filename = filename.replace(/~\//, '')
  let fileDbEntry = await manifestDb.get('SELECT fileID, domain, relativePath, file from Files where relativePath LIKE ? ORDER BY relativePath', filename)

  if (!fileDbEntry || !fileDbEntry.fileID) { throw new Error(`requested file ${filename} was not found in Manifest.db; check syntax and drop ~/ if present.`) }

  let contentsStream = await fs.createReadStream(path.join(backupPath, backupDir, fileDbEntry.fileID.slice(0, 2), fileDbEntry.fileID))

  let fileInfo = (await bplist.parseBuffer(fileDbEntry.file))[0]
  let fileData = fileInfo['$objects'][fileInfo['$top'].root.UID]
  let protectionClass = fileData.ProtectionClass
  let wrappedFileKey = fileInfo['$objects'][fileData.EncryptionKey.UID]['NS.data'].slice(4)

  let fileUnwrapKey = await importKWKey(keybag.classes[protectionClasses[protectionClass]].KEY)
  let unwrappedFileKey = await unwrapKey(wrappedFileKey, fileUnwrapKey)
  return decryptAESCBC(unwrappedFileKey, contentsStream)
}

/**
 * Dump all attachements from a list of SMS
 * @param {String} backupDir
 * @param {Object} keybag
 * @param {Database} manifestDb
 * @param {Object[]} smsList - the complete results of a DB query of the right format against the SMS database
 */
async function dumpSMSAttachments (backupDir, keybag, manifestDb, smsList) {
  let attachedFiles = await Promise.all(smsList.filter(sms => sms.attachedFile).map(sms => {
    return decryptFile(backupDir, sms.attachedFile, keybag, manifestDb).then(contentStream => ({contentStream, filename: sms.attachedFile}))
  }))
  return Promise.all(attachedFiles.map(attachedFile => writeOutFileStream(path.basename(attachedFile.filename), attachedFile.contentStream)))
}

async function main () {
  const [, , password, phoneNumber] = process.argv

  let dirs = await readdir(backupPath)
  let backupDir = dirs[0]
  console.log(`Found backups: ${dirs} in ${backupPath}; using ${backupDir}`)

  // read the keybag from the manifest plist
  let keybag = await readKeybag(backupDir)

  // construct a passkey from the input password (slow)
  console.log('Constructing passkey...')
  let passkey = await importKWKey(await constructPasskey(password, keybag))

  // unwrap all the keys in the keybag with the passkey
  await Promise.all(Object.values(keybag.classes)
    .filter(keyClass => keyClass.WRAP === 2) // we only know how to handle / care about this wrap type
    .map(keyClass => unwrapKey(keyClass.WPKY, passkey).then(unwrappedKey => { keyClass.KEY = unwrappedKey }))
  )

  // decrypt the database of per file keys (manifest.db) with the info from manifest.plist decrypted with the passkey,
  // write it to disk and open it as SQLite file (there doesn't seem to be a way to open it as a stream instead of having to write it out)
  let manifest = await readManifestKey(backupDir)
  let unwrappedManifestKey = await unwrapKey(manifest.wrappedKey, await importKWKey(keybag.classes[protectionClasses[manifest.keyClass]].KEY))
  let manifestReadStream = fs.createReadStream(path.join(backupPath, backupDir, 'Manifest.db'))
  let manifestDbFile = await writeOutFileStream('Manifest.db', decryptAESCBC(unwrappedManifestKey, manifestReadStream), true)
  let manifestDb = await sqlite.open(manifestDbFile)

  console.log('Decrypting SMS database file...')
  let decryptedContents = await decryptFile(backupDir, smsDatabaseFilename, keybag, manifestDb)
  await writeOutFileStream(path.basename(smsDatabaseFilename), decryptedContents)

  const query = `
  SELECT DATETIME(date/1000000000 + 978307200, 'unixepoch', 'localtime') AS date, 
  h.id AS number, m.service AS service,
  CASE is_from_me WHEN 0 THEN "Received" WHEN 1 THEN "Sent" ELSE "Unknown" END AS type,
  text AS text,
  CASE cache_has_attachments WHEN 1 THEN a.filename ELSE NULL END AS attachedFile
  FROM message AS m
  LEFT OUTER JOIN handle AS h ON h.rowid = m.handle_id
  LEFT OUTER JOIN message_attachment_join AS maj ON maj.message_id = m.rowid
  LEFT OUTER JOIN attachment AS a ON a.rowid = maj.attachment_id
  WHERE h.id = ?
  ORDER BY m.rowid ASC;`

  console.log('Dumping SMS database contents...')
  let smsdb = await sqlite.open(path.basename(smsDatabaseFilename))
  let smsList = await smsdb.all(query, phoneNumber)

  await dumpSMSAttachments(backupDir, keybag, manifestDb, smsList)

  let outputPdfFile = fs.createWriteStream('test.pdf')
  let pdfDoc = new PDFDocument()
  pdfDoc.pipe(outputPdfFile)

  pdfDoc.font('Helvetica')

  //const allowedFiletypes = ['.gif', '.png', '.jpg', '.jpeg', '.bmp']
  const allowedFiletypes = ['.png', '.jpg', '.jpeg']

  var lastType = 'Received'
  smsList.map(sms => {
    let me = sms.type === 'Received'
    let options = {align: me  ? 'right' : 'left'}
    pdfDoc.fillColor(me ? 'blue' : 'black')
    if (sms.attachedFile) {
      if (allowedFiletypes.includes(path.extname(sms.attachedFile).toLowerCase())) {
        return pdfDoc.image(path.basename(sms.attachedFile), {align: options.align, fit: [200, 200]})
      }
      else {
        return pdfDoc.text(`<attachment format not yet supported for ${path.basename(sms.attachedFile)}`, options)
      }
    }
    // if (sms.text === '\uFFFC') { // U+FFFC = 'OBJECT REPLACEMENT CHARACTER', i.e. an attachment only message
    //   return pdfDoc.text('<attachments not yet supported>', options)
    // }
    pdfDoc.text(sms.text, options)
    if (lastType === sms.type) {
      pdfDoc.moveDown()
    }
    else {
      lastType = sms.type
      pdfDoc.moveDown(3)
    }
    
  })
  pdfDoc.end()

  await manifestDb.close()
  await smsdb.close()
  await unlink(manifestDbFile)
}

main()
