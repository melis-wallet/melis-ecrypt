var aes = require('browserify-aes')
var assert = require('assert')
var createHash = require('create-hash')
var scrypt = require('scryptsy')
var xor = require('buffer-xor')


// SHA256(SHA256(buffer))
function sha256x2 (buffer) {
  buffer = createHash('sha256').update(buffer).digest()
  return createHash('sha256').update(buffer).digest()
}

function Ecrypt (versions) {
  if (!(this instanceof Ecrypt)) return new Ecrypt()

  // BIP38 recommended
  this.scryptParams = {
    N: 16384,
    r: 8,
    p: 8
  }
}

Ecrypt.prototype.encrypt = function (buffer, passphrase, saltNonce, progressCallback) {
  assert.equal(buffer.length, 32, 'Invalid secret length')

  var secret = new Buffer(passphrase, 'utf8')
  var salt = sha256x2(saltNonce).slice(0, 4)

  var N = this.scryptParams.N
  var r = this.scryptParams.r
  var p = this.scryptParams.p

  var scryptBuf = scrypt(secret, salt, N, r, p, 64, progressCallback)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var xorBuf = xor(buffer, derivedHalf1)
  var cipher = aes.createCipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  cipher.setAutoPadding(false)
  cipher.end(xorBuf)

  var cipherText = cipher.read()



  var prefix = new Buffer(4)
  prefix.writeUInt8(0x1f, 0)
  prefix.writeUInt8(0x42, 1)
  prefix.writeUInt8(0x00, 2)
  prefix.writeUInt8(0x00, 3)

  prefix = xor(prefix, salt)

  return Buffer.concat([prefix, salt, cipherText])
}


Ecrypt.prototype.decrypt = function (encData, passphrase, progressCallback) {
  // 40 bytes: 4 bytes prefix, 36 bytes payload
  assert.equal(encData.length, 40, 'Invalid Ecrypt data length')

  var prefix = encData.slice(0, 3)
  var salt = encData.slice(4, 8)

  prefix = xor(prefix, salt)

  // first byte is always 0x01
  assert.equal(prefix.readUInt8(0), 0x1f, 'Invalid Ecrypt prefix')
  assert.equal(prefix.readUInt8(1), 0x42, 'Invalid Ecrypt type')

  passphrase = new Buffer(passphrase, 'utf8')


  var N = this.scryptParams.N
  var r = this.scryptParams.r
  var p = this.scryptParams.p
  var scryptBuf = scrypt(passphrase, salt, N, r, p, 64, progressCallback)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var privKeyBuf = encData.slice(8, 8 + 32)
  var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  decipher.setAutoPadding(false)
  decipher.end(privKeyBuf)

  var plainText = decipher.read()
  var secret = xor(plainText, derivedHalf1)

  return {
    secret: secret
  }
}


module.exports = Ecrypt
