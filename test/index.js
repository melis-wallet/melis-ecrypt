var assert = require('assert')
var Ecrypt = require('../')
var fixtures = require('./fixtures')
var randomBytes = require('randombytes')


describe('ecrypt', function () {
  var ecrypt
  beforeEach(function () {
    ecrypt = new Ecrypt()
  })


  describe('decrypt', function () {
    fixtures.valid.forEach(function (f) {
      it('should decrypt ' + f.description, function () {
        var data = new Buffer(f.output, 'hex');

        assert.equal(ecrypt.decrypt(data, f.passphrase).secret.toString('hex'), f.plainText)
      })
    })


    fixtures.invalid.decrypt.forEach(function (f) {
      it('should throw ' + f.description, function () {
        assert.throws(function () {
          var data = new Buffer(f.output, 'hex');
          ecrypt.decrypt(data, f.passphrase)
        }, new RegExp(f.description, 'i'))
      })
    })

  })

  describe('encrypt', function () {
    fixtures.valid.forEach(function (f) {
      if (f.decryptOnly) return

      it('should encrypt ' + f.description, function () {
        var nonce = new Buffer(f.nonce, 'hex');
        var data = new Buffer(f.plainText, 'hex');

        assert.equal(ecrypt.encrypt(data, f.passphrase, nonce).toString('hex'), f.output, 'hex')
      })
    })
  })

})
