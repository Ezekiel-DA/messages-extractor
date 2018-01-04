const crypto = require('crypto')
const webcrypto = require('@trust/webcrypto')
const fs = require('fs')
const process = require('process')
const path = require('path')
const { promisify } = require('util')
const bplist = require('bplist-parser')
const sqlite = require('sqlite')
const uuidv4 = require('uuid/v4')

const backupPath = path.join(process.env.APPDATA, 'Apple Computer/MobileSync/Backup')

const protectionClasses = ['Unused',
'NSFileProtectionComplete', 'NSFileProtectionCompleteUnlessOpen', 'NSFileProtectionCompleteUntilFirstUserAuthentication',
'NSFileProtectionNone', 'NSFileProtectionRecovery?', 'kSecAttrAccessibleWhenUnlocked', 'kSecAttrAccessibleAfterFirstUnlock',
'kSecAttrAccessibleAlways', 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly', 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
'kSecAttrAccessibleAlwaysThisDeviceOnly']

// these key types describe class keys, not the generic keybag itself, and should be bundled together by Protection Class
const classKeyTypes = ['CLAS', 'WRAP', 'WPKY', 'KTYP', 'PBKY', 'UUID']

// promisify some commonly used native APIs
const [pbkdf2, readdir, readfile, writefile, unlink, parseplistFile] = [crypto.pbkdf2, fs.readdir, fs.readFile, fs.writeFile, fs.unlink, bplist.parseFile].map(promisify)

/**
 * Read the raw (encrypted) contents of a file in the backup, returning a Buffer
 * @param {String} filename - the file to process in the backup directory
 * @param {String} backupDir - the backup directory
 */
async function readRawFileFromBackup (filename, backupDir) {
  return readfile(path.join(backupPath, backupDir, filename))
}

async function readFileById (backupDir, fileid) {
  return readfile(path.join(backupPath, backupDir, fileid.slice(0, 2), fileid))
}

async function readManifest (backupDir) {
  return parseplistFile(path.join(backupPath, backupDir, 'Manifest.plist'))
}

/**
 * Writes a file to the temporary directory with the given contents, returning a Promise for the actual (unique) full filepath.
 * File paths are made unique by prepending a UUID to them.
 * @param {String} filename
 * @param {Buffer} contents
 */
async function writeTmpFile (filename, contents) {
  let uuid = uuidv4()
  let uniqueFilename = path.join(process.env.TMPDIR || process.env.TMP || process.env.TEMP, uuid + '-' + filename)
  return writefile(uniqueFilename, contents)
  .then(() => uniqueFilename)
}

/**
 * Extract the manifest key from Manifest.plist and return it's class and wrapped key (to be unwrapped)
 * @param {*} backupDir
 */
async function readManifestKey (backupDir) {
  let manifest = (await readManifest(backupDir))[0].ManifestKey
  let keyClass = manifest.readInt32LE()
  let wrappedKey = manifest.slice(4)
  return {keyClass, wrappedKey}
}

/**
 * Import a Key Wrapping key (in the RFC3394 sense)
 * @param {*} key - the raw unwrapping key
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
  let manifest = await readManifest(backupDir)
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
 * Decrypt some data through AES256 in CBC mode. Assumes 0 IV, returns a Buffer of the decrypted data.
 * @param {Buffer} unwrappedKey - the unwrapped key to use
 * @param {Buffer} data - a buffer of the data to decrypt
 */
function decryptAESCBC (unwrappedKey, data) {
  let dbDecrypter = crypto.createDecipheriv('aes-256-cbc', unwrappedKey, new Buffer(16))
  return Buffer.concat([dbDecrypter.update(data), dbDecrypter.final()])
}

async function main () {
  const [, , password, fileToExtract] = process.argv

  console.log(`Searching for backups in ${backupPath}`)

  let dirs = await readdir(backupPath)
  console.log(`Found backups: ${dirs}`)

  console.log('Reading keybag from manifest...')
  let keybag = await readKeybag(dirs[0])
  // console.log(keybag)

  console.log('Constructing passkey...')
  let passkey = await constructPasskey(password, keybag)
  // console.log(passkey)

  console.log('Unwraping keys in keybag...')
  let userKey = await importKWKey(passkey)
  let keyUnwrapping = await Promise.all(Object.values(keybag.classes).map(keyClass => {
    if (keyClass.WRAP !== 2) {
      return Promise.resolve('unhandled wrap type')
    }
    return unwrapKey(keyClass.WPKY, userKey)
    .then(unwrappedKey => {
      keyClass.KEY = unwrappedKey
    })
  }))
  // console.log(keybag)

  console.log('Decrypting database...')
  let manifest = await readManifestKey(dirs[0])
  let manifestUnwrapKey = await importKWKey(keybag.classes[protectionClasses[manifest.keyClass]].KEY)
  let unwrappedManifestKey = await unwrapKey(manifest.wrappedKey, manifestUnwrapKey)

  let rawDB = await readRawFileFromBackup('Manifest.db', dirs[0])
  let dbfile = await writeTmpFile('Manifest.db', decryptAESCBC(unwrappedManifestKey, rawDB))
  let db = await sqlite.open(dbfile)
  let res = await db.get('SELECT fileID, domain, relativePath, file from Files where relativePath LIKE ? ORDER BY relativePath', fileToExtract)
  // console.log(res)

  if (!res.fileID) {
    console.log(`requested file ${fileToExtract} was not found in Manifest.db; check syntax and drop ~/ if present.`)
    process.exit(1)
  }

  let contents = await readFileById(dirs[0], res.fileID)
  // console.log(contents)

  let fileInfo = (await bplist.parseBuffer(res.file))[0]
  let fileData = fileInfo['$objects'][fileInfo['$top'].root.UID]
  let protectionClass = fileData.ProtectionClass
  let wrappedFileKey = fileInfo['$objects'][fileData.EncryptionKey.UID]['NS.data'].slice(4)

  let fileUnwrapKey = await importKWKey(keybag.classes[protectionClasses[protectionClass]].KEY)
  let unwrappedFileKey = await unwrapKey(wrappedFileKey, fileUnwrapKey)
  // let f = await writeTmpFile('sms.db', decryptAESCBC(unwrappedFileKey, contents).slice(0, fileData.Size)) // this should truncate the decrypted contents to the right length but appears to break things ?
  // let outputFilename = await writeTmpFile(path.basename(fileToExtract), decryptAESCBC(unwrappedFileKey, contents))
  // console.log(outputFilename)
  await writefile(path.basename(fileToExtract), decryptAESCBC(unwrappedFileKey, contents))
  
  await db.close()
  //await unlink(dbfile)
}

main()
