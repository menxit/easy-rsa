const ursa = require('ursa');

module.exports = {

    generateKeys: (bits, exp) => {
        const key = ursa.generatePrivateKey(bits || 1024, exp || 65537);
        const private_key = key.toPrivatePem().toString('ascii');
        const public_key = key.toPublicPem().toString('ascii');
        return { private_key, public_key };
    },

    encrypt: (text, key) => {
        try {
            key = ursa.createPrivateKey(key);
            return key.privateEncrypt(text, 'utf8', 'base64');
        } catch(error) {
            key = ursa.createPublicKey(key);
            return key.encrypt(text, 'utf8', 'base64');
        }
    },

    decrypt: (encrypted, key) => {
        try {
            key = ursa.createPublicKey(key);
            return key.publicDecrypt(encrypted, 'base64', 'utf8');
        } catch(error) {
            key = ursa.createPrivateKey(key);
            return key.decrypt(encrypted, 'base64', 'utf8')
        }
    },

};
